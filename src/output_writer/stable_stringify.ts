// src/output_writer/stable_stringify.ts

export function stableStringify(value: any): string {
    if (value === null) return "null";
    const t = typeof value;

    if (t === "number" || t === "boolean") return JSON.stringify(value);
    if (t === "string") return JSON.stringify(value);

    if (Array.isArray(value)) {
        return "[" + value.map(stableStringify).join(",") + "]";
    }

    if (t === "object") {
        const keys = Object.keys(value).sort(); // UTF-16 lex order like JS sort()
        return (
            "{" +
            keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") +
            "}"
        );
    }

    // undefined, function, symbol, bigint
    throw new Error("UNSUPPORTED_JSON_TYPE");
}
