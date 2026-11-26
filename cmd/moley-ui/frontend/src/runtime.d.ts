// The parts of the Wails runtime the window uses. The app serves the
// runtime itself at /wails/runtime.js; tsconfig maps that path here.
export declare const Call: { ByName(name: string, ...args: unknown[]): Promise<any> };
export declare const Events: { On(name: string, callback: (event: { data: any }) => void): () => void };
