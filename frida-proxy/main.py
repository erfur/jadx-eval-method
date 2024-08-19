import sys
from time import sleep
import frida
import adb
import logging
import os
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="frida.log",
    filemode="a",
)

logger = logging.getLogger(__name__)


def eval_method(pkg_name, class_name, method_name, method_arg):
    device = frida.get_usb_device()

    if pkg_name not in [app.identifier for app in device.enumerate_applications()]:
        logger.error(f"Package {pkg_name} not found")
        print("failed")
        sys.exit(1)

    pid = device.spawn([pkg_name])
    session = device.attach(pid)

    method_info = {
        "class": class_name,
        "name": method_name,
        "arg": method_arg,
    }

    with open("_agent.js", encoding="utf8") as f:
        script = session.create_script(f.read()) #, runtime="v8")

    def on_message(message, data):
        payload = message["payload"]
        if payload["cmd"] == "init":
            logger.info("Init")
            logger.info(f"Method: {method_info}")
            ThreadPoolExecutor().submit(script.exports_sync.eval_method, method_info)
        elif payload["cmd"] == "log":
            logger.info(payload["message"])
        elif payload["cmd"] == "methodResult":
            logger.info(f"Method Result: {payload['result']}")
            print(payload["result"])
        else:
            logger.info(payload)

    script.on("message", on_message)
    script.load()

    logger.info("Resume")
    device.resume(pid)

    device.on("process-crashed", lambda pid: sys.exit(1))

    for _ in range(10):
        sleep(1)


def install_apk(apk_path):
    devices = adb.get_devices()

    if not devices:
        print("No devices connected")
        sys.exit(1)

    device = devices[0]

    device = adb.get_device(device)
    device.install(apk_path, True)

    print("installed")


def main(args):
    if args[0] == "install":
        install_apk(args[1])
    elif args[0] == "eval":
        eval_method(*args[1:])
    else:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
