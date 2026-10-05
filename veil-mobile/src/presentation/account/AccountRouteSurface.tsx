import React from 'react';
import { RouteSurface } from '../../interfacePreview/RouteSurface';
import { WallpaperSurface } from '../../interfacePreview/WallpaperSurface';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { useAccountAppearance } from '../appearance/AccountAppearance';

export function AccountRouteSurface(props: Omit<React.ComponentProps<typeof RouteSurface>, 'background'>) {
  const { c } = usePresentation();
  const appearance = useAccountAppearance();
  return <RouteSurface {...props} background={<WallpaperSurface c={c} {...appearance} />} />;
}
