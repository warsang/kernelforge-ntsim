/**
 * bcd.mjs — Boot Configuration Data hive virtualization.
 *
 * Anti-cheat drivers read \Registry\Machine\BCD to prove they run on a real
 * boot: element keys must exist and their values must have the right type for
 * the element-ID format nibble. Ported from KEVLAR's AutoPopulateBcdElement:
 * queried-but-missing elements are synthesized as typed zero values.
 *
 * Element ID layout (BCD): top nibble = data type, low 28 bits = element id.
 *   1 = string (REG_SZ)      2 = integer (REG_DWORD)
 *   3 = boolean (REG_DWORD)  4/5/6/7 = objects/lists/devices (REG_BINARY)
 */

const encoder = new TextEncoder();

/** Common boot-manager elements with plausible values. */
export const BCD_ELEMENTS = {
  0x12000004: { type: 1, data: encoder.encode("\0") },                       // description
  0x12000002: { type: 1, data: encoder.encode("\\Windows\\system32\\winload.exe\0") },
  0x21000001: { type: 4, data: Uint8Array.from([0, 0, 0, 0]) },              // integer
  0x23000003: { type: 4, data: Uint8Array.from([0, 0, 0, 0]) },              // boolean
  0x25000004: { type: 3, data: new Uint8Array(8) },                          // integer list
  0x11000001: { type: 3, data: new Uint8Array(16) },                         // device
};

export const BCD_ELEMENT_NAMES = {
  0x12000004: "BcdLibraryString_Description",
  0x12000002: "BcdLibraryString_ApplicationPath",
  0x21000001: "BcdLibraryInteger_...",
  0x23000003: "BcdLibraryBoolean_AutoRecoveryEnabled",
  0x25000004: "BcdLibraryIntegerList_...",
  0x11000001: "BcdLibraryDevice_ApplicationDevice",
};

/**
 * Typed-zero value for a BCD element ID (used for elements the driver asks
 * for that were not seeded). Returns null when the ID is not BCD-shaped.
 */
export function bcdValueForElement(elementId) {
  let id;
  try {
    if (typeof elementId === "string") {
      // Element key names are hex without the 0x prefix.
      if (!/^[0-9a-f]+$/i.test(elementId)) return null;
      id = Number(BigInt.asUintN(32, BigInt("0x" + elementId)));
    } else {
      id = Number(BigInt.asUintN(32, BigInt(elementId)));
    }
  } catch {
    return null;
  }
  if (id === 0) return null;
  const fmt = (id >>> 28) & 0xf;
  switch (fmt) {
    case 1: return { type: 1, data: encoder.encode("\0") };   // REG_SZ
    case 2: return { type: 4, data: Uint8Array.from([0, 0, 0, 0]) }; // REG_DWORD
    case 3: return { type: 4, data: Uint8Array.from([0, 0, 0, 0]) }; // REG_DWORD bool
    case 4: return { type: 3, data: new Uint8Array(8) };      // object
    case 5: return { type: 3, data: new Uint8Array(16) };     // object list
    case 6: return { type: 3, data: new Uint8Array(8) };      // integer list
    case 7: return { type: 3, data: new Uint8Array(16) };     // device
    default: return null;
  }
}

const BCD_ROOT = "\\Registry\\Machine\\BCD";
const BCD_OBJECT = `${BCD_ROOT}\\00000000\\Objects\\{00000000-0000-0000-0000-000000000000}`;

/**
 * Seed the BCD hive. Idempotent; requires kernel.registry to exist.
 */
export function installBcdHive(kernel, opts = {}) {
  if (kernel.bcdSeeded) return kernel;
  if (!(kernel.registry instanceof Map)) return kernel;
  kernel.bcdSeeded = true;
  kernel.registry.set(BCD_ROOT, new Map([
    ["Description", { type: 1, data: encoder.encode("Windows Boot Manager\0") }],
    ["Objects", { type: 3, data: new Uint8Array(16) }],
  ]));
  kernel.registry.set(`${BCD_ROOT}\\00000000`, new Map());
  kernel.registry.set(BCD_OBJECT, new Map([
    ["Description", { type: 1, data: encoder.encode("Windows Boot Manager\0") }],
  ]));
  let seeded = 0;
  for (const [id, value] of Object.entries(opts.elements ?? BCD_ELEMENTS)) {
    const name = Number(id).toString(16);
    kernel.registry.set(`${BCD_OBJECT}\\Elements\\${name}`, new Map([
      // BCD stores the element id as a DWORD named "Element", then the data
      // under "Value" (real hives use the element name; both are queried).
      ["Element", { type: 4, data: Uint8Array.from([
        Number(id) & 0xff, (Number(id) >>> 8) & 0xff,
        (Number(id) >>> 16) & 0xff, (Number(id) >>> 24) & 0xff]) }],
      ["Value", { type: value.type, data: value.data }],
    ]));
    seeded++;
  }
  kernel.registry.set(`${BCD_OBJECT}\\Elements`, new Map());
  kernel.bcdElementCount = seeded;
  return kernel;
}
