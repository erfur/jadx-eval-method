import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from time import sleep

import adb
import click
import frida
import grpc
from loguru import logger
from proto.rpc_pb2 import (
    EvalReply,
    EvalRequest,
    EvalStatus,
    InstallReply,
    InstallRequest,
    InstallStatus,
)
from proto.rpc_pb2_grpc import (
    FridaEvalProxyServicer,
    add_FridaEvalProxyServicer_to_server,
)

_cleanup_coroutines = []


class FridaEvalProxyRpc(FridaEvalProxyServicer):
    async def install(
        self,
        request: InstallRequest,
        context: grpc.aio.ServicerContext,
    ) -> InstallReply:
        try:
            devices = adb.get_devices()

            if not devices:
                logger.error(f"Error installing application: No devices found")
                return InstallReply(status=InstallStatus.INSTALL_ERR_NO_DEVICES)

            device_id = devices[0]  # use the first device

            logger.info(f"Using device: {device_id}")

            device = adb.get_device(device_id)
            result = device.install(request.package_path, False)

            # TODO check if the app is already installed

            if "Success" in result:
                logger.info(f"Installed {request.package_path} successfully.")
                return InstallReply(status=InstallStatus.INSTALL_OK)
        except Exception as e:
            logger.exception(f"Error installing application: {e}")
            return InstallReply(status=InstallStatus.INSTALL_ERROR, error=str(e))

    async def eval(
        self,
        request: EvalRequest,
        context: grpc.aio.ServicerContext,
    ) -> EvalReply:
        device = frida.get_usb_device()

        if request.package_name not in [
            app.identifier for app in device.enumerate_applications()
        ]:
            logger.error(f"Package {request.package_name} not found")
            return EvalReply(status=EvalStatus.EVAL_ERR_PACKAGE_NOT_FOUND)

        try:
            pid = device.spawn([request.package_name])
        except frida.NotSupportedError:
            logger.error("Cannot spawn app, check if frida server is running.")
            return EvalReply(status=EvalStatus.EVAL_ERR_SPAWN_FAILED)

        logger.info(f"Spawned {request.package_name} with PID: {pid}")

        session = device.attach(pid)

        method_info = {
            "class": request.class_name,
            "name": request.method_name,
            "arg": request.method_args[0],
        }

        # TODO fix path, cwd might be different
        with open("_agent.js", encoding="utf8") as f:
            script = session.create_script(f.read())  # , runtime="v8")

        result_event = asyncio.Event()
        method_result = EvalReply(status=EvalStatus.EVAL_ERROR)

        def on_message(message, data):
            if message["type"] == "send" and message["payload"]["type"] == "result":
                logger.info(f"Method Result: {message["payload"]['result']}")
                method_result.status = EvalStatus.EVAL_OK
                method_result.result = message["payload"]["result"]
            elif message["type"] == "send" and message["payload"]["type"] == "error":
                logger.error(f"Error: {message["payload"]['description']}")
                method_result.status = EvalStatus.EVAL_ERR_SCRIPT_ERROR
                method_result.error = message["payload"]["description"]
            elif message["type"] == "error":
                logger.error(f"Frida error: {message['description']}")
                logger.error(f"Frida error stack: {message['stack']}")
                method_result.status = EvalStatus.EVAL_ERR_FRIDA_ERROR
                method_result.error = message["description"]
            else:
                logger.error(f"Unknown message: {message}")

            # on_message is called from a different thread
            loop.call_soon_threadsafe(result_event.set)

        script.on("message", lambda message, data: on_message(message, data) and result_event.set())
        script.load()
        script.set_log_handler(lambda level, text: logger.info(f"[{device.id}][{pid}][{level}] {text}"))
        script.post(
            {
                "method_info": method_info,
            }
        )

        def crash_handler(pid):
            logger.error(f"Process crashed, pid: {pid}")
            method_result.status = EvalStatus.EVAL_ERR_PROCESS_CRASHED
            result_event.set()

        device.on("process-crashed", crash_handler)

        def on_timeout(task: asyncio.Task):
            if task.cancelled():
                return
            
            logger.error("Timeout")
            method_result.status = EvalStatus.EVAL_ERR_TIMEOUT
            result_event.set()

        # set a timeout
        timeout_task = asyncio.create_task(asyncio.sleep(5))
        timeout_task.add_done_callback(on_timeout)

        logger.info("Resume")
        device.resume(pid)

        await result_event.wait()
        timeout_task.cancel()
        return method_result


async def serve(addr: str, listen_port: int) -> None:
    server = grpc.aio.server()
    add_FridaEvalProxyServicer_to_server(FridaEvalProxyRpc(), server)
    server.add_insecure_port(f"{addr}:{listen_port}")
    await server.start()

    async def server_graceful_shutdown():
        logger.info("Shutting down...")
        await server.stop(1)

    _cleanup_coroutines.append(server_graceful_shutdown())
    await server.wait_for_termination()


@click.command()
@click.option("--port", default=50051, help="Port to listen on")
def main(port):
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG",
        format="<green>{time:HH:mm:ss:SSS}</green> | <level>{message}</level>",
    )
    log = logger.bind(context="main")
    log.info(f"Starting server on localhost:{port}")

    global loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(serve("localhost", port))
    finally:
        loop.run_until_complete(*_cleanup_coroutines)
        loop.close()


if __name__ == "__main__":
    main()
