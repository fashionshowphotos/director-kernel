/**
 * Schema Validator - JSON schema validation for artifacts
 * Implements MS3 contract: schema_validator
 */

export interface ValidationError {
    path: string;
    message: string;
}

export interface ValidationResult {
    valid: boolean;
    errors: ValidationError[];
}

export interface JsonSchema {
    type: string;
    properties?: Record<string, JsonSchema>;
    required?: string[];
    items?: JsonSchema;
    enum?: any[];
    pattern?: string;
    minimum?: number;
    maximum?: number;
}

export class SchemaValidator {
    private schemas: Map<string, JsonSchema> = new Map();

    registerSchema(schemaId: string, schema: JsonSchema): void {
        this.schemas.set(schemaId, schema);
    }

    validate(artifact: any, schemaId: string): ValidationResult {
        const schema = this.schemas.get(schemaId);
        if (!schema) {
            return {
                valid: false,
                errors: [{ path: '', message: `Schema not found: ${schemaId}` }],
            };
        }

        const errors: ValidationError[] = [];
        this.validateValue(artifact, schema, '', errors);

        return {
            valid: errors.length === 0,
            errors,
        };
    }

    private validateValue(
        value: any,
        schema: JsonSchema,
        path: string,
        errors: ValidationError[]
    ): void {
        // Type validation
        const actualType = this.getType(value);
        if (schema.type && actualType !== schema.type) {
            errors.push({
                path,
                message: `Expected type ${schema.type}, got ${actualType}`,
            });
            return;
        }

        // Object validation
        if (schema.type === 'object' && schema.properties) {
            if (typeof value !== 'object' || value === null) {
                errors.push({ path, message: 'Expected object' });
                return;
            }

            // Required fields
            if (schema.required) {
                for (const req of schema.required) {
                    if (!(req in value)) {
                        errors.push({ path: `${path}.${req}`, message: 'Required field missing' });
                    }
                }
            }

            // Validate properties
            for (const [key, propSchema] of Object.entries(schema.properties)) {
                if (key in value) {
                    this.validateValue(value[key], propSchema, `${path}.${key}`, errors);
                }
            }
        }

        // Array validation
        if (schema.type === 'array' && schema.items) {
            if (!Array.isArray(value)) {
                errors.push({ path, message: 'Expected array' });
                return;
            }

            for (let i = 0; i < value.length; i++) {
                this.validateValue(value[i], schema.items, `${path}[${i}]`, errors);
            }
        }

        // Enum validation
        if (schema.enum && !schema.enum.includes(value)) {
            errors.push({
                path,
                message: `Value must be one of: ${schema.enum.join(', ')}`,
            });
        }

        // Pattern validation
        if (schema.pattern && typeof value === 'string') {
            const regex = new RegExp(schema.pattern);
            if (!regex.test(value)) {
                errors.push({ path, message: `Value does not match pattern: ${schema.pattern}` });
            }
        }

        // Number range validation
        if (typeof value === 'number') {
            if (schema.minimum !== undefined && value < schema.minimum) {
                errors.push({ path, message: `Value ${value} < minimum ${schema.minimum}` });
            }
            if (schema.maximum !== undefined && value > schema.maximum) {
                errors.push({ path, message: `Value ${value} > maximum ${schema.maximum}` });
            }
        }
    }

    private getType(value: any): string {
        if (value === null) return 'null';
        if (Array.isArray(value)) return 'array';
        return typeof value;
    }
}
