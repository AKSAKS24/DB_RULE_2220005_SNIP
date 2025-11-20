from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(
    title="Rule 2220005 — Obsolete KONV/Condition Technique Scanner",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Obsolete mappings (SAP Note 2220005)
# ---------------------------------------------------------------------------
OBSOLETE_TABLE_MAP: Dict[str, str] = {
    "KONV": "PRCD_ELEMENTS",
}

OBSOLETE_TYPE_MAP: Dict[str, str] = {
    "KONV": "PRCD_ELEMENTS",
    "DZAEHK": "VFPRC_COND_COUNT",
    "DZAEKO": "VFPRC_COND_COUNT_HEAD",
}

# ---------------------------------------------------------------------------
# Models (unified header + findings style)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None      # ObsoleteTableUsage / ObsoleteTypeDeclaration
    severity: Optional[str] = None         # always "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None          # single line, \n escaped


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
# Any DML involving KONV (SELECT/INSERT/UPDATE/DELETE)
SQL_KONV_RE = re.compile(
    r"""(?imx)
        (SELECT[\s\S]+?FROM|INSERT\s+INTO|UPDATE|DELETE\s+FROM)   # DML start
        [\s\S]{0,1000}?                                          # up to 1000 chars lookahead
        \b(?P<table>KONV)\b                                      # KONV as whole word
        (?!\w)                                                   # not KONVA etc
    """
)

# Declarations that use KONV, DZAEHK, DZAEKO as TYPE/LIKE (table or line)
DECL_KONV_RE = re.compile(
    r"""(?imx)
        \b(?P<full>
            (DATA|TYPES|FIELD-SYMBOLS|CONSTANTS)
            [^.\n]*?
            \b(?:TYPE|LIKE)\b\s*(?:TABLE\s+OF\s+|\s+)? 
            (?P<dtype>KONV|DZAEHK|DZAEKO)\b
        )
    """
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Return the full line containing the span (start, end).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def make_finding(
    unit: Unit,
    src: str,
    match_start: int,
    match_end: int,
    issues_type: str,
    message: str,
    suggestion: str,
) -> Finding:
    """
    Build a Finding with absolute line numbers and a single-line snippet.
    Severity is always 'error'.
    """
    base_start = unit.start_line or 0

    line_in_block = src[:match_start].count("\n") + 1
    snippet_line = get_line_snippet(src, match_start, match_end)
    snippet_line_count = snippet_line.count("\n") + 1

    starting_line_abs = base_start + line_in_block
    ending_line_abs = base_start + line_in_block + snippet_line_count

    return Finding(
        prog_name=unit.pgm_name,
        incl_name=unit.inc_name,
        types=unit.type,
        blockname=unit.name,
        starting_line=starting_line_abs,
        ending_line=ending_line_abs,
        issues_type=issues_type,
        severity="error",
        message=message,
        suggestion=suggestion,
        snippet=snippet_line.replace("\n", "\\n"),
    )


# ---------------------------------------------------------------------------
# Core scanning logic (scan-only, no remediation)
# ---------------------------------------------------------------------------
def analyze_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings: List[Finding] = []

    # --- DML statements on KONV ---
    for m in SQL_KONV_RE.finditer(src):
        table = m.group("table").upper()
        replacement = OBSOLETE_TABLE_MAP.get(table, "")
        start_off, end_off = m.span()

        msg = (
            f"{table} table is obsolete in S/4HANA (SAP Note 2220005), "
            f"replaced by {replacement}."
        )
        sug = f"Rewrite the statement using {replacement} and adjust related logic."

        findings.append(
            make_finding(
                unit=unit,
                src=src,
                match_start=start_off,
                match_end=end_off,
                issues_type="ObsoleteTableUsage",
                message=msg,
                suggestion=sug,
            )
        )

    # --- Obsolete TYPE/LIKE declarations ---
    for m in DECL_KONV_RE.finditer(src):
        dtype = m.group("dtype").upper()
        replacement = OBSOLETE_TYPE_MAP.get(dtype, "")
        start_off, end_off = m.span()

        msg = (
            f"{dtype} type is obsolete (SAP Note 2220005), "
            f"use {replacement} instead."
        )
        sug = f"Change the declaration using {replacement} and adapt the logic accordingly."

        findings.append(
            make_finding(
                unit=unit,
                src=src,
                match_start=start_off,
                match_end=end_off,
                issues_type="ObsoleteTypeDeclaration",
                message=msg,
                suggestion=sug,
            )
        )

    out = Unit(**unit.model_dump())
    out.findings = findings if findings else None
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_kondition_obsolete_array(units: List[Unit] = Body(...)):
    """
    Scan an array of units; return only those that have findings
    (positive-only behaviour).
    """
    results: List[Unit] = []
    for u in units:
        res = analyze_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_kondition_obsolete_single(unit: Unit = Body(...)):
    """
    Scan a single unit; always return the unit with findings attached (if any).
    """
    return analyze_unit(unit)


@app.get("/health")
def health():
    return {"ok": True, "rule": "2220005", "version": "2.0"}
