import re
import hmac
import hashlib

from encryption import load_key


# =========================================================
# SEARCH SECURITY CONTEXT
# =========================================================

SEARCH_CONTEXT = b"SECURE_MEDICAL_RECORD_SEARCH_V1"


# =========================================================
# NORMALIZE TEXT
# =========================================================

def normalize_text(text):
    """
    Converts text into a consistent searchable format.
    """

    if text is None:
        return ""

    text = str(text).strip().lower()

    # Keep letters, numbers, spaces and hyphens.
    text = re.sub(r"[^a-z0-9\s\-]", " ", text)

    # Remove extra spaces.
    text = re.sub(r"\s+", " ", text)

    return text


# =========================================================
# EXTRACT KEYWORDS
# =========================================================

def extract_keywords(text):
    """
    Extracts searchable keywords from text.
    """

    normalized = normalize_text(text)

    if not normalized:
        return []

    words = normalized.split()

    stop_words = {
        "a",
        "an",
        "the",
        "is",
        "am",
        "are",
        "was",
        "were",
        "has",
        "have",
        "had",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "with"
    }

    keywords = []

    for word in words:

        if word in stop_words:
            continue

        if len(word) < 2:
            continue

        if word not in keywords:
            keywords.append(word)

    return keywords


# =========================================================
# GENERATE SEARCH TOKEN
# =========================================================

def generate_search_token(keyword):
    """
    Generates a deterministic HMAC-SHA256 token.

    Plaintext keyword is NOT stored.
    """

    normalized_keyword = normalize_text(keyword)

    if not normalized_keyword:
        return None

    encryption_key = load_key()

    # Derive a separate HMAC key from the encryption key.
    hmac_key = hmac.new(
        encryption_key,
        SEARCH_CONTEXT,
        hashlib.sha256
    ).digest()

    # Generate deterministic search token.
    token = hmac.new(
        hmac_key,
        normalized_keyword.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return token


# =========================================================
# GENERATE TOKENS FROM TEXT
# =========================================================

def generate_tokens_from_text(text):
    """
    Converts a text into HMAC search tokens.
    """

    keywords = extract_keywords(text)

    tokens = []

    for keyword in keywords:

        token = generate_search_token(keyword)

        if token and token not in tokens:
            tokens.append(token)

    return tokens


# =========================================================
# GENERATE RECORD SEARCH TOKENS
# =========================================================

def generate_record_search_tokens(fields):
    """
    Generates search tokens for multiple medical record fields.

    Example fields:
        patient_id
        patient_name
        phone
        diagnosis
        symptoms
        medical_history
        prescription
        test_results
        doctor_notes
    """

    results = []

    if not isinstance(fields, dict):
        return results

    for field_name, field_value in fields.items():

        if field_value is None:
            continue

        keywords = extract_keywords(field_value)

        for keyword in keywords:

            token = generate_search_token(keyword)

            if token:

                item = {
                    "token": token,
                    "field_name": field_name
                }

                if item not in results:
                    results.append(item)

    return results


# =========================================================
# CREATE QUERY TOKEN
# =========================================================

def create_query_token(keyword):
    """
    Creates a token for a single search keyword.
    """

    return generate_search_token(keyword)


# =========================================================
# CREATE QUERY TOKENS
# =========================================================

def create_query_tokens(query):
    """
    Converts a user's search query into HMAC tokens.
    """

    keywords = extract_keywords(query)

    tokens = []

    for keyword in keywords:

        token = generate_search_token(keyword)

        if token and token not in tokens:
            tokens.append(token)

    return tokens


# =========================================================
# VERIFY SEARCH TOKEN
# =========================================================

def verify_search_token(keyword, existing_token):
    """
    Safely compares a generated token with an existing token.
    """

    generated_token = generate_search_token(keyword)

    if not generated_token or not existing_token:
        return False

    return hmac.compare_digest(
        generated_token,
        existing_token
    )


# =========================================================
# SEARCH SECURITY INFORMATION
# =========================================================

def get_search_security_info():

    return {
        "algorithm": "HMAC-SHA256",
        "search_context": "SECURE_MEDICAL_RECORD_SEARCH_V1",
        "plaintext_keywords_stored": False,
        "search_tokens_stored": True,
        "encryption_key_required": True
    }


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    print("Testing privacy-preserving search...\n")

    keyword1 = "diabetes"
    keyword2 = "diabetes"
    keyword3 = "fever"

    token1 = generate_search_token(keyword1)
    token2 = generate_search_token(keyword2)
    token3 = generate_search_token(keyword3)

    print("Keyword 1:")
    print(keyword1)

    print("\nToken 1:")
    print(token1)

    print("\nKeyword 2:")
    print(keyword2)

    print("\nToken 2:")
    print(token2)

    print("\nKeyword 3:")
    print(keyword3)

    print("\nToken 3:")
    print(token3)

    print("\nSame keyword produces same token:")

    print(token1 == token2)

    print("\nDifferent keyword produces different token:")

    print(token1 != token3)

    print("\nSecurity information:")

    print(get_search_security_info())