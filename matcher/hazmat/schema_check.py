"""Validate the register without a dependency.

`jsonschema` is not installed everywhere, so the same check must run here as in CI,
or a schema drift is only ever discovered on a push. This implements the subset of
JSON Schema the placard schema actually uses, and shouts about any keyword it does
not implement rather than silently ignoring it.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# the subset we implement; anything else in a schema is an error, not a shrug
KEYWORDS = {'$schema', 'title', 'description', 'type', 'required', 'properties',
            'additionalProperties', 'enum', 'pattern', 'minimum', 'maximum',
            'items', 'minItems', 'maxItems', 'maxLength', 'oneOf', 'default'}
TYPES = {'string': str, 'integer': int, 'number': (int, float), 'boolean': bool, 'array': list, 'object': dict}


def validate(instance, schema, path='$'):
    errors = []
    for keyword in schema:
        if keyword not in KEYWORDS:
            errors.append('%s: schema uses %r, which this validator does not implement' % (path, keyword))
    if 'type' in schema:
        expected = TYPES.get(schema['type'])
        if expected and not isinstance(instance, expected):
            return errors + ['%s: expected %s, got %s' % (path, schema['type'], type(instance).__name__)]
    if 'enum' in schema and instance not in schema['enum']:
        errors.append('%s: %r is not one of %s' % (path, instance, schema['enum']))
    if isinstance(instance, str):
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], instance):
            errors.append('%s: %r does not match %s' % (path, instance, schema['pattern']))
        if 'maxLength' in schema and len(instance) > schema['maxLength']:
            errors.append('%s: %d characters, over the %d limit' % (path, len(instance), schema['maxLength']))
    if isinstance(instance, int) and not isinstance(instance, bool):
        if 'minimum' in schema and instance < schema['minimum']:
            errors.append('%s: %r is below %s' % (path, instance, schema['minimum']))
        if 'maximum' in schema and instance > schema['maximum']:
            errors.append('%s: %r is above %s' % (path, instance, schema['maximum']))
    if isinstance(instance, dict):
        for key in schema.get('required', []):
            if key not in instance:
                errors.append('%s: missing required key %r' % (path, key))
        for key, value in instance.items():
            if key in schema.get('properties', {}):
                errors += validate(value, schema['properties'][key], '%s.%s' % (path, key))
            elif schema.get('additionalProperties') is False:
                errors.append('%s: unexpected key %r' % (path, key))
            elif isinstance(schema.get('additionalProperties'), dict):
                errors += validate(value, schema['additionalProperties'], '%s.%s' % (path, key))
        if 'oneOf' in schema:
            matches = sum(1 for option in schema['oneOf'] if not validate(instance, option, path))
            if matches != 1:
                errors.append('%s: matched %d of the oneOf options' % (path, matches))
    if isinstance(instance, list):
        if 'minItems' in schema and len(instance) < schema['minItems']:
            errors.append('%s: needs at least %d items' % (path, schema['minItems']))
        if 'maxItems' in schema and len(instance) > schema['maxItems']:
            errors.append('%s: allows at most %d items' % (path, schema['maxItems']))
        if 'items' in schema:
            for index, item in enumerate(instance):
                errors += validate(item, schema['items'], '%s[%d]' % (path, index))
    return errors


ROOT = Path(__file__).resolve().parents[2]


def check(register=None, schema_path=None, confirmations=None):
    """Every placard validates, ids are unique, filenames match, confirmed ships a repro.

    Defaults are repo-rooted, like everywhere else: a check that only passes when run
    from the right directory is a check that lies.
    """
    register = Path(register or ROOT / 'register' / 'placards')
    confirmations = Path(confirmations or ROOT / 'confirmations')
    if schema_path:
        schema_path = Path(schema_path)
    else:
        sibling = register.parent / 'schema' / 'placard.schema.json'
        schema_path = sibling if sibling.is_file() else ROOT / 'register' / 'schema' / 'placard.schema.json'
    schema = json.loads(schema_path.read_text())
    errors = []
    ids = {}
    for path in sorted(register.glob('*.json')):
        try:
            placard = json.loads(path.read_text())
        except ValueError as exc:
            errors.append('%s: not valid json: %s' % (path.name, exc))
            continue
        errors += validate(placard, schema, path.name)
        if placard.get('id') != path.stem:
            errors.append('%s: id %r does not match the filename' % (path.name, placard.get('id')))
        if placard.get('id') in ids:
            errors.append('%s: duplicate id %s' % (path.name, placard.get('id')))
        ids[placard.get('id')] = path.name
        matcher = placard.get('matcher') or {}
        if not (matcher.get('require_all') or matcher.get('require_any')):
            errors.append('%s: matcher asks for nothing' % path.name)
        for key in ('require_all', 'require_any', 'require_none_of'):
            for selector in matcher.get(key) or []:
                if not re.fullmatch(r'0x[0-9a-f]{8}', selector):
                    errors.append('%s: %s %r is not a 4-byte selector' % (path.name, key, selector))
        if placard.get('tier') == 'confirmed':
            if not placard.get('reproduction'):
                errors.append('%s: confirmed but ships no reproduction' % path.name)
            records = list(confirmations.glob('%s-*.json' % placard['id'])) if confirmations.is_dir() else []
            if not records:
                errors.append('%s: confirmed but has no confirmation record' % path.name)
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(prog='hazmat validate')
    parser.add_argument('--register', default=None)
    parser.add_argument('--confirmations', default=None)
    args = parser.parse_args(argv)
    errors = check(args.register, None, args.confirmations)
    for error in errors:
        print('  %s' % error)
    placards = len(list(Path(args.register).glob('*.json')))
    print('%d placards, %d problem(s)' % (placards, len(errors)))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
