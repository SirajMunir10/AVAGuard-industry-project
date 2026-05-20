"""
AVAGuard Web Portal - PII Scrubbing Utility

Masks personally identifiable information in reports and exports.
SuperAdmin sees full data; other roles see masked PII.
"""

import re


def mask_email(email):
    """
    Mask an email address: u***r@example.com

    >>> mask_email('user@example.com')
    'u***r@example.com'
    >>> mask_email('a@b.co')
    'a***a@b.co'
    """
    if not email or '@' not in email:
        return email
    local, domain = email.rsplit('@', 1)
    if len(local) <= 2:
        masked_local = local[0] + '***'
    else:
        masked_local = local[0] + '***' + local[-1]
    return f"{masked_local}@{domain}"


def mask_upn(upn):
    """Mask a UPN (User Principal Name) — same format as email."""
    return mask_email(upn)


def mask_org_name(name):
    """
    Mask an organization name: show first 3 chars + asterisks.

    >>> mask_org_name('Contoso Ltd')
    'Con*****'
    """
    if not name:
        return name
    if len(name) <= 3:
        return name[0] + '***'
    return name[:3] + '*****'


def scrub_text(text):
    """
    Regex-based scrubber for freeform text fields.
    Detects and masks email addresses embedded in strings.
    """
    if not text:
        return text
    # Match email pattern and replace with masked version
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.sub(email_pattern, lambda m: mask_email(m.group()), str(text))


def scrub_report_context(context, user):
    """
    Scrub PII from report template context based on user role.

    SuperAdmin sees full PII. All other roles see masked data.

    Args:
        context: dict of template context variables
        user: the requesting User object

    Returns:
        dict with PII masked (if applicable)
    """
    if getattr(user, 'role', '') == 'SUPER_ADMIN':
        return context  # Full visibility for SuperAdmin

    scrubbed = dict(context)

    # Mask the requesting user's own email in the report
    if 'user' in scrubbed and hasattr(scrubbed['user'], 'email'):
        # Don't modify the actual user object — create a display dict
        u = scrubbed['user']
        scrubbed['report_user_email'] = mask_email(u.email)
        scrubbed['report_user_name'] = getattr(u, 'full_name', '')

    # Mask organization name
    if 'organization' in scrubbed and scrubbed['organization']:
        org = scrubbed['organization']
        if hasattr(org, 'name'):
            scrubbed['report_org_name'] = mask_org_name(org.name)

    return scrubbed
