class Logger {
    isDebug: boolean = false;

    toggleDebug() {
        this.isDebug = !this.isDebug;
    }

    debug(message: any): void {
        if (this.isDebug) {
            this.info(message);
        }
    }

    info(message: any): void {
        send({
            type: "info",
            payload: message,
        })
    }

    error(message: any) {
        send({
            type: "error",
            payload: message,
        })
    }

    fatal(message: any) {
        throw(message);
    }

    data(blob: any) {
        send({
            type: "blob",
        }, blob)
    }

    json(data: any) {
        send({
            type: "json",
            payload: JSON.stringify(data),
        })
    }
}

export const log = new Logger();