/**
 * System Prompts for Transform Engine
 * 
 * Each transform type has its own prompt generator function.
 * Prompts are parameterized where needed (e.g., target language).
 */

import { getMs5ToMs4Prompt } from './ms5_to_ms4';
import { getMs4ToMs3Prompt } from './ms4_to_ms3';
import { getMs3ToMs2Prompt } from './ms3_to_ms2';
import { getMs2ToMs2_5Prompt } from './ms2_to_ms2_5';
import { getMs2_5ToMs3Prompt } from './ms2_5_to_ms3';
import { getIntentToMs5Prompt } from './intent_to_ms5';
import { getDefaultPrompt } from './default';
import { getPatchPrompt } from './patch';

// Re-export all prompts
export { getMs5ToMs4Prompt, getMs4ToMs3Prompt, getMs3ToMs2Prompt, getMs2ToMs2_5Prompt, getMs2_5ToMs3Prompt, getIntentToMs5Prompt, getDefaultPrompt, getPatchPrompt };

export function getSystemPrompt(
    transformType: string,
    globalInstruction: string,
    options?: { targetLanguage?: string; langInstructions?: string; diagnostics?: string; stubFiles?: string[] }
): string {
    switch (transformType) {
        case 'ms5_to_ms4':
            return getMs5ToMs4Prompt(globalInstruction);
        case 'ms4_to_ms3':
            return getMs4ToMs3Prompt(globalInstruction);
        case 'ms3_to_ms2':
            return getMs3ToMs2Prompt(globalInstruction, options?.targetLanguage || 'typescript', options?.langInstructions || '');
        case 'ms2_to_ms2_5':
            return getMs2ToMs2_5Prompt(globalInstruction);
        case 'ms2_5_to_ms3':
            return getMs2_5ToMs3Prompt(globalInstruction);
        case 'intent_to_ms5':
            return getIntentToMs5Prompt(globalInstruction);
        default:
            return getDefaultPrompt();
    }
}
