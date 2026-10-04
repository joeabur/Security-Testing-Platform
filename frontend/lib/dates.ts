/**
 * `<input type="datetime-local">` reads and writes its value as local
 * time, with no timezone marker. `Date#toISOString()` is UTC, so using it
 * to build a default value shows (and round-trips) a time offset from the
 * real local time by the viewer's UTC offset — hours in the future for
 * anyone west of UTC, which made a freshly granted authorization read as
 * "not yet valid" the moment it was submitted.
 */
export function toLocalDatetimeInputValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}
