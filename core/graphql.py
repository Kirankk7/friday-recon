"""GraphQL helpers — parse an introspection result into an operation map + build queries, so the
REST-shaped oracles can speak POST-body GraphQL. Pure/offline: no network, no detection here (the active
probing + reuse of the SQLi/NoSQLi signatures lives in ultron.graphql_check). Found via the DVGA
generalization test + the real MediaMarkt target (both GraphQL). Authorized targets only.
"""
import re

INTROSPECTION_QUERY = (
    "query{__schema{queryType{fields{name args{name type{kind name ofType{kind name ofType{kind name}}}}}} "
    "mutationType{fields{name args{name type{kind name ofType{kind name}}}}}}}")

_ID_ARG = re.compile(r"(^id$|_id$|id$|uuid|guid|number|ref$|reference)", re.I)


def _arg_type(a):
    """Unwrap NON_NULL/LIST wrappers to the underlying named type (ID/Int/String/...)."""
    t = a.get("type") or {}
    seen = 0
    while t and seen < 8:
        if t.get("name"):
            return t["name"]
        t = t.get("ofType") or {}
        seen += 1
    return ""


def parse_schema(introspection_json):
    """{'queries':[(name,[(arg,type)]),...], 'mutations':[...]} from an introspection response dict, or None."""
    s = ((introspection_json or {}).get("data") or {}).get("__schema")
    if not s:
        return None

    def ops(key):
        out = []
        for f in (s.get(key) or {}).get("fields") or []:
            out.append((f.get("name", ""), [(a.get("name", ""), _arg_type(a)) for a in f.get("args") or []]))
        return out
    return {"queries": ops("queryType"), "mutations": ops("mutationType")}


def single_id_queries(schema):
    """Queries taking exactly one id-ish/scalar arg -> BOLA candidates (node(id:...)). [(op, arg, type)]."""
    out = []
    for name, args in (schema or {}).get("queries", []):
        if len(args) == 1:
            an, at = args[0]
            if _ID_ARG.search(an) or at in ("ID", "Int", "Long"):
                out.append((name, an, at))
    return out


def string_args(schema, section="queries"):
    """(op, arg) pairs whose arg is a String/ID -> injection candidates."""
    out = []
    for name, args in (schema or {}).get(section, []):
        for an, at in args:
            if at in ("String", "ID"):
                out.append((name, an))
    return out


def build_query(op, arg=None, value=None, selection="__typename"):
    """Minimal query string: {op(arg:value){selection}}. Scalar value inlined (quoted if non-numeric str)."""
    if arg is None:
        return "{%s}" % op
    if isinstance(value, str) and not value.isdigit():
        v = '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    else:
        v = str(value)
    return "{%s(%s:%s){%s}}" % (op, arg, v, selection)
