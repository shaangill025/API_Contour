import {sessionFenced} from './api.ts';

// Each result is published only after its own session check and while its selection is current.
export async function historyRead<T>(
  read: (signal: AbortSignal, view: string)=>Promise<T>, signal: AbortSignal,
  onView: (view: string)=>void, current: ()=>boolean,
  publish: (value: T)=>void, fail: (error: unknown)=>void, finish: ()=>void,
): Promise<void> {
  try {
    const value=await sessionFenced(read,signal,onView);
    if (current()) publish(value);
  } catch (error) {
    if (current()) fail(error);
  } finally {
    if (current()) finish();
  }
}
