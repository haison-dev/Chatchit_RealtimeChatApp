let cached: boolean | undefined;

/** Whether this browser can create a WebGL context (needed for the 3D scene). Cached after the first check. */
export const canUseWebGL = (): boolean => {
  if (cached !== undefined) return cached;
  try {
    const canvas = document.createElement("canvas");
    cached = !!(canvas.getContext("webgl2") ?? canvas.getContext("webgl"));
  } catch {
    cached = false;
  }
  return cached;
};
