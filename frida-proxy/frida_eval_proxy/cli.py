import asyncio
import sys
import click
import grpc
from loguru import logger
from android_toolkit.a import install_application

from proto.rpc_pb2 import EvalReply, EvalRequest, InstallReply, InstallRequest
from proto.rpc_pb2_grpc import (
    FridaEvalProxyServicer,
    add_FridaEvalProxyServicer_to_server,
)


class FridaEvalProxyRpc(FridaEvalProxyServicer):
    async def install(
        self,
        request: InstallRequest,
        context: grpc.aio.ServicerContext,
    ) -> InstallReply:
        try:
            install_application(request.package_name)
        except Exception as e:
            logger.error(f"Error installing application: {e}")
            return InstallReply(status=-1, message=str(e))

        return InstallReply(status=0, message="test")

    async def eval(
        self,
        request: EvalRequest,
        context: grpc.aio.ServicerContext,
    ) -> EvalReply:
        return EvalReply(status=0, message="test", result="test")


async def serve(addr: str, listen_port: int) -> None:
    server = grpc.aio.server()
    add_FridaEvalProxyServicer_to_server(FridaEvalProxyRpc(), server)
    server.add_insecure_port(f"{addr}:{listen_port}")
    await server.start()
    await server.wait_for_termination()


@click.command()
@click.option("--port", default=50051, help="Port to listen on")
def main(port):
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG",
        format="<green>{time:HH:mm:ss:SSS}</green> | {extra[context]} | <level>{message}</level>",
    )
    log = logger.bind(context="main")
    log.info(f"Starting server on localhost:{port}")
    asyncio.run(serve("localhost", port))


if __name__ == "__main__":
    main()
