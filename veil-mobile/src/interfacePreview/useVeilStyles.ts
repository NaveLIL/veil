import { useMemo } from 'react';
import { usePresentation } from './PresentationContext';
import type { Palette } from './appearance';
/** Palette changes invalidate styles; typing/operations do not rebuild them. */
export function useVeilStyles<T>(factory: (c: Palette) => T): T {
  const { c } = usePresentation();
  return useMemo(() => factory(c), [factory, c]);
}
