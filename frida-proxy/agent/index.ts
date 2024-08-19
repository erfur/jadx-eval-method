import { JavaUseOnceLoaded } from "./dyn_use.js";
import { log } from "./logger.js";
import { StringDecoder } from "string_decoder";
import { Buffer } from "buffer";

// Java.performNow(() => {
//     JavaUseOnceLoaded("re.obfuscator.challenge01.AHGILuuQdMj", () => {
//         send({
//             cmd: "init",
//         })
//         toast("Hello from agent");
//     });
// });

Java.perform(() => {
    send({
        cmd: "init",
    })
    toast("Hello from agent")
})

interface MethodInfo {
    class: string,
    name: string,
    arg: string,
}

function unhexlify(hex: string): string {
    // unhexlify a utf string
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }

    const decoder = new StringDecoder('utf8');
    return decoder.write(Buffer.from(bytes));
}

function evalMethod(method: MethodInfo) {
    try {
        const cls = Java.use(method.class);
        const result = cls[method.name](unhexlify(method.arg));
        const resultStr = result.toString();
        toast("Result: " + resultStr);
        send({
            cmd: "methodResult",
            result: resultStr,
        })
    } catch (error: any) {
        toast("Error: " + error);
        send({
            cmd: "methodError",
            error: error.toString(),
        })
    }
}

function toast(msg: string) {
    Java.scheduleOnMainThread(() => {
        Java.use("android.widget.Toast")
            .makeText(
                Java.use("android.app.ActivityThread")
                    .currentApplication()
                    .getApplicationContext(),
                Java.use("java.lang.StringBuilder").$new(msg), 0
            ).show();
    });
}

rpc.exports = {
    evalMethod,
}