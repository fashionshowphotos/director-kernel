// src/output_writer/index.ts

import { OutputWriter } from "./types";
import { OutputWriterImpl } from "./writer";

export function createOutputWriter(): OutputWriter {
    return new OutputWriterImpl();
}

export * from "./types";
