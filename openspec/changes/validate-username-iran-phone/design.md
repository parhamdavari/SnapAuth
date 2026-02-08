## Context

The SnapAuth application currently validates username fields with only a minimum length constraint (`min_length=3`). The application requires usernames to be Iran mobile phone numbers for business alignment, but this constraint is not enforced at the API layer.

**Current State:**
- `UserCreateRequest.username`: `Field(..., min_length=3, description="Username")`
- `UserUpdateRequest.username`: `Field(None, min_length=3, description="New username")`
- No format validation exists
- FusionAuth backend accepts any string as username

**Stakeholders:**
- API clients creating/updating users (breaking change impact)
- Backend validation layer (Pydantic schemas)
- FusionAuth integration (username format consistency)

## Goals / Non-Goals

**Goals:**
- Enforce Iran mobile phone number format (09XXXXXXXXX) for all username fields
- Provide clear, actionable validation error messages
- Apply validation consistently across user creation and update endpoints
- Maintain backward compatibility with existing password and metadata validation

**Non-Goals:**
- Validate phone number ownership or existence (no SMS verification)
- Modify FusionAuth username storage format
- Add phone number formatting or normalization (e.g., converting +989... to 09...)
- Retroactively validate existing usernames in database

## Decisions

### Decision 1: Use Pydantic field_validator over Field constraints

**Rationale:**
- `Field(pattern=...)` provides basic regex validation but limited error message customization
- `field_validator` allows custom error messages and complex validation logic
- Consistent with existing `model_validator` usage in `UserUpdateRequest`
- Better testability and maintainability

**Alternatives considered:**
- Custom validator function: Less idiomatic for Pydantic v2
- Field(pattern=...): Limited error message control

**Implementation:**
```python
from pydantic import field_validator
import re

IRAN_PHONE_PATTERN = re.compile(r'^09\d{9}$')

@field_validator('username')
@classmethod
def validate_username_iran_phone(cls, v: str) -> str:
    if not IRAN_PHONE_PATTERN.match(v):
        raise ValueError('Username must be an Iran mobile number (09XXXXXXXXX)')
    return v
```

### Decision 2: Use compiled regex pattern constant

**Rationale:**
- Pattern: `^09\d{9}$` (starts with 09, followed by exactly 9 more digits)
- Compile once at module level for performance
- Clear pattern constant name for maintainability
- Simple pattern sufficient for format validation (no complex lookaheads needed)

**Alternatives considered:**
- String length + prefix check: Less elegant, more verbose
- External validation library: Overkill for single format check

### Decision 3: Apply validator to both UserCreateRequest and UserUpdateRequest

**Rationale:**
- Consistency: Same validation rules for create and update operations
- DRY: Share validation logic between schemas
- Implementation: Add same `@field_validator` to both classes

**Implementation approach:**
```python
# Option A: Duplicate validator in both classes (CHOSEN)
# - Simple, explicit, no magic
# - Easy to modify independently if needed

# Option B: Shared base class or mixin
# - More complex, premature abstraction for single field
# - Not chosen: YAGNI (You Aren't Gonna Need It)
```

### Decision 4: Return HTTP 422 for validation errors

**Rationale:**
- FastAPI/Pydantic automatically returns 422 for validation errors
- Semantic HTTP status: 422 Unprocessable Entity indicates client input validation failure
- Consistent with existing Pydantic validation behavior in the application
- No custom exception handling needed

### Decision 5: Error message format

**Rationale:**
- Message: `"Username must be an Iran mobile number (09XXXXXXXXX)"`
- Provides clear expected format with example pattern
- Concise and actionable for API clients
- Consistent with Pydantic validation error message style

## Risks / Trade-offs

### Risk: Breaking change for existing API clients
**Impact:** Clients attempting to create users with non-phone usernames will receive 422 errors

**Mitigation:**
- Document breaking change in API changelog
- Coordinate with frontend teams before deployment
- Consider phased rollout if multiple clients exist

### Risk: Username uniqueness constraints
**Impact:** Limited pool of valid usernames (Iran has ~100M possible phone numbers)

**Trade-off:** Business requirement acceptance - phone numbers are intended user identifiers

**Mitigation:** None needed - this is intended behavior per business requirements

### Risk: No existing username migration
**Impact:** Existing users with non-phone usernames remain in database

**Trade-off:** New constraint only applies to new/updated usernames

**Consideration:** If existing invalid usernames cause issues, a separate data migration task would be needed (out of scope for this change)

### Risk: International users cannot register
**Impact:** Only users with Iran phone numbers can create accounts

**Trade-off:** Accepted limitation per business requirements

**Note:** Future internationalization would require revisiting this constraint

## Migration Plan

**Not applicable** - This is a new constraint, not a data migration.

**Deployment:**
1. Deploy code with new validation
2. Existing users unaffected (constraint only applies to new API requests)
3. Monitor validation error rates in first 24-48 hours

**Rollback:**
- Simple: Revert code changes to remove field validators
- No database changes required
