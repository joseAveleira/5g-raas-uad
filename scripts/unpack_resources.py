"""Restore exact source bytes from the checked gzip files; preserve existing files."""
from pathlib import Path
import gzip, hashlib, json, shutil

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    for entry in json.loads((ROOT/'recursos/manifest.json').read_text()):
        source = ROOT/entry['stored_as']
        target = ROOT/'recursos'/entry['file']
        if digest(source) != entry['stored_sha256']:
            raise ValueError(f'Stored checksum mismatch: {source.name}')
        if target.exists():
            if digest(target) != entry['original_sha256']:
                raise ValueError(f'Existing file differs; not overwritten: {target.name}')
        else:
            temporary = target.with_suffix(target.suffix+'.unpacking')
            with gzip.open(source, 'rb') as inp, temporary.open('xb') as out:
                shutil.copyfileobj(inp, out)
            if digest(temporary) != entry['original_sha256']:
                raise ValueError(f'Restored checksum mismatch: {target.name}')
            temporary.rename(target)
        print(f'Verified {target.name}')

if __name__ == '__main__':
    main()
