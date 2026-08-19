export type Row = Record<string, any>
export type LoadState<T> = { data?: T; error?: string; loading: boolean }
