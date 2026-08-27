/**
 * Parses a VergiliusProject type page (HTML) into flat field tables.
 *
 * Page shape (verified Aug 2026, CC0 per terms.html):
 *   Vergilius Project | \_EPROCESS
 *   ## \_EPROCESS
 *   ...
 *   ```
 *   `copy
 *   //0xa40 bytes (sizeof)
 *   struct \_EPROCESS
 *   {
 *   struct [\_KPROCESS](URL) Pcb; //0x0
 *   VOID\* UniqueProcessId; //0x440
 *   ULONG JobNotReallyActive:1; //0x460
 *   ...
 *   };
 *   ```
 */

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", nbsp: " " };

function decodeEntities(s) {
  return s.replace(/&(#?\w+);/g, (m, ent) => ENTITIES[ent] ?? m);
}

/**
 * Reduce a Vergilius page (raw HTML or pre-rendered text) to plain struct lines:
 * - raw HTML: struct code lives inside <div id="copyblock">...</div>
 * - rendered text/markdown: fenced ``` block
 */
export function extractCodeBlock(pageHtml) {
  const cbStart = pageHtml.indexOf('<div id="copyblock">');
  if (cbStart !== -1) {
    const from = cbStart + '<div id="copyblock">'.length;
    const end = pageHtml.indexOf("</code>", from);
    const stop = end === -1 ? pageHtml.indexOf("</div>", from) : end;
    let body = pageHtml.slice(from, stop === -1 ? undefined : stop);
    // drop the copy <button ...>...</button> if present at the start
    body = body.replace(/<button[\s\S]*?<\/button>/g, "");
    body = body.replace(/<[^>]+>/g, ""); // strip all remaining tags, keep inner text of <a>
    return decodeEntities(body);
  }
  return pageHtml; // assume already-plain/fenced text
}

/** Strip markdown escaping/link syntax + html remnants from one line. */
export function cleanLine(raw) {
  let s = raw;
  s = s.replace(/\[([^\]]*)\]\([^)]*\)/g, "$1"); // [label](url) -> label
  s = s.replace(/\\([_*[\]`()#~])/g, "$1"); // escaped chars
  return s.trim();
}

const FIELD_RE =
  /^(?<decl>[^;]+);\s*\/\/(?<offset>0x[0-9a-fA-F]+)(?:\s+(?<note>.*))?$/;

/**
 * @param {string} pageHtml raw html/mdx-ish page content
 * @returns {{name: string|null, totalSize: number|null, fields: Array<object>}}
 */
export function parseTypePage(pageHtml) {
  const lines = extractCodeBlock(pageHtml).split(/\r?\n/);
  const nameMatch = pageHtml.match(/<title>Vergilius Project \| _?([A-Za-z0-9_]+)<\/title>/)
    ?? pageHtml.match(/^##\s+\\?_?([A-Za-z0-9_]+)/m);
  const typeName = nameMatch ? nameMatch[1] : null;

  // isolate fenced block (markdown-style pages only)
  const fenceStart = lines.findIndex((l) => l.trim() === "```");
  let body = lines;
  if (fenceStart !== -1) {
    let fenceEnd = -1;
    for (let i = fenceStart + 1; i < lines.length; i++) {
      if (lines[i].trim() === "```") { fenceEnd = i; break; }
    }
    body = lines.slice(fenceStart + 1, fenceEnd === -1 ? lines.length : fenceEnd);
  }

  const fields = [];
  let totalSize = null;

  for (const rawLine of body) {
    const line = cleanLine(rawLine);
    if (!line || line === "copy") continue;

    const sizeM = line.match(/^\/\/(0x[0-9a-fA-F]+)\s+bytes\s+\(sizeof\)/);
    if (sizeM) {
      totalSize = parseInt(sizeM[1], 16);
      continue;
    }

    const m = line.match(FIELD_RE);
    if (!m) continue; // braces, 'union', 'struct' headers without ';'

    const decl = m.groups.decl.trim();
    const offset = parseInt(m.groups.offset, 16);

    // derive kind info from decl
    const isBitfield = /:\s*\d+$/.test(decl);
    const arrM = decl.match(/^(?<base>.+?)\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[(?<count>\d*)\]$/);
    let base = decl, fieldName = null, arrayCount = null;
    if (arrM) {
      base = arrM.groups.base.trim();
      fieldName = arrM.groups.name;
      arrayCount = arrM.groups.count ? parseInt(arrM.groups.count, 10) : null; // [] flexible
    } else {
      const nm = decl.match(/^(?<base>.+?)\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)$/);
      if (nm) { base = nm.groups.base.trim(); fieldName = nm.groups.name; }
    }

    const ptr = /\*$/.test(base) || /^\w+\s*\*$/.test(base);
    fields.push({
      name: fieldName ?? "(anon)",
      offset,
      decl,
      base: base.replace(/\s*volatile$/, "").trim(),
      pointer: ptr,
      bitfield: isBitfield,
      array: arrayCount,
    });
  }

  return { name: typeName, totalSize, fields };
}

/** Build {fieldName: entry} map (first occurrence wins on collisions). */
export function indexByName(fields) {
  const idx = {};
  for (const f of fields) {
    if (f.name !== "(anon)" && !(f.name in idx)) idx[f.name] = f;
  }
  return idx;
}
