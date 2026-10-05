/** Presentation metadata, never a provider URI or native transfer capability. */
export type Attachment =
  | {
      kind: 'image';
      name: string;
      fixture: 'landscape';
      width: number;
      height: number;
    }
  | { kind: 'file'; name: string; mediaType: string; bytes: number };
export type Transfer = {
  phase:
    | 'sending'
    | 'waiting'
    | 'unknown'
    | 'failed'
    | 'complete'
    | 'cancelled';
  progress: number;
  attempt: number;
  fail: boolean;
};
