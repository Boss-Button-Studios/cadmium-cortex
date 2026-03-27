import os
import subprocess

class ConstitutionUnversionedError(Exception):
    pass

class ConstitutionLengthError(Exception):
    pass

def load_constitution(filepath: str = 'constitution/residential/constitution.md') -> str:
    """Loads and validates the constitution file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Constitution file missing at {filepath}")

    # Enforce Git versioning
    try:
        result = subprocess.run(
            ['git', 'log', '-1', '--oneline', '--', filepath],
            capture_output=True, text=True, check=True
        )
        if not result.stdout.strip():
            raise ConstitutionUnversionedError(
                f"File {filepath} has no Git history. You must commit it first."
            )
    except subprocess.CalledProcessError:
        raise ConstitutionUnversionedError(
            f"Git check failed for {filepath}. Is the repository initialized?"
        )

    # Read and enforce length constraint
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    if len(lines) > 20:
        raise ConstitutionLengthError(
            f"Constitution exceeds 20 lines (currently {len(lines)}). Keep context narrow."
        )
        
    return "".join(lines)
