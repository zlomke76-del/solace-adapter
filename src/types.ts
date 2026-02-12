// src/types.ts

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue =
  | JsonPrimitive
  | JsonObject
  | JsonArray;

export interface JsonObject {
  [key: string]: JsonValue;
}

export interface JsonArray extends Array<JsonValue> {}

export interface ActorRef {
  id: string;
}

export interface IntentObject extends JsonObject {
  intent: string;
  actor: ActorRef;
  context?: JsonObject;
}

export interface GateRequest {
  intent: IntentObject;
  execute: JsonObject;
  acceptance: JsonObject;
}
