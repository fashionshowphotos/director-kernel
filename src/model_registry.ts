// model_registry.ts - MC2-LITE Model Registry
export interface ModelInfo {
    id: string;
    pricing: {
        prompt: number; // USD per million tokens
        completion: number; // USD per million tokens
    };
    contextWindow: number;
    supportsJsonMode: boolean;
}

export class ModelRegistry {
    private static instance: ModelRegistry;
    private models: Map<string, ModelInfo> = new Map();

    private constructor() {
        this.initializeDefaults();
    }

    public static getInstance(): ModelRegistry {
        if (!ModelRegistry.instance) {
            ModelRegistry.instance = new ModelRegistry();
        }
        return ModelRegistry.instance;
    }

    private initializeDefaults() {
        // Hydrate from known frozen constants or config
        const defaults: ModelInfo[] = [
            {
                id: 'anthropic/claude-3.5-haiku',
                pricing: { prompt: 0.25, completion: 1.25 },
                contextWindow: 200000,
                supportsJsonMode: false  // Anthropic models don't support response_format: json_object
            },
            {
                id: 'anthropic/claude-3-haiku',
                pricing: { prompt: 0.25, completion: 1.25 },
                contextWindow: 200000,
                supportsJsonMode: false
            },
            {
                id: 'openai/gpt-4o-mini',
                pricing: { prompt: 0.15, completion: 0.60 },
                contextWindow: 128000,
                supportsJsonMode: true
            },
            {
                id: 'deepseek/deepseek-chat',
                pricing: { prompt: 0.14, completion: 0.28 },
                contextWindow: 64000,
                supportsJsonMode: true
            },
            {
                id: 'deepseek/deepseek-coder',
                pricing: { prompt: 0.14, completion: 0.28 },
                contextWindow: 64000,
                supportsJsonMode: true
            },
            {
                id: 'meta-llama/llama-3.1-70b-instruct',
                pricing: { prompt: 0.59, completion: 0.59 },
                contextWindow: 128000,
                supportsJsonMode: false  // Via OpenRouter, JSON mode support varies
            },
            {
                id: 'anthropic/claude-3.5-sonnet',
                pricing: { prompt: 3.00, completion: 15.00 },
                contextWindow: 200000,
                supportsJsonMode: false
            },
            {
                id: 'openai/gpt-4o',
                pricing: { prompt: 2.50, completion: 10.00 },
                contextWindow: 128000,
                supportsJsonMode: true
            },
            {
                id: 'google/gemini-1.5-pro',
                pricing: { prompt: 3.50, completion: 10.50 },
                contextWindow: 2000000,
                supportsJsonMode: true
            }
        ];

        defaults.forEach(m => this.models.set(m.id, m));
    }

    public getModelInfo(modelId: string): ModelInfo | undefined {
        return this.models.get(modelId);
    }

    public registerModel(info: ModelInfo) {
        this.models.set(info.id, info);
    }
}
