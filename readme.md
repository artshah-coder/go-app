# RealWorld API Implementation

A backend implementation for the [RealWorld](https://github.com/gothinkster/realworld) demo project (Conduit - Medium clone).

## Key Features
- User authentication with **stateful sessions** (via Authorization header)
- Article management with various filtering options
- Layered architecture (handlers → repositories → DB)

## Implementation Details
- Partial implementation of RealWorld specs (core entities only)
- Integration tests covering main workflows
- Optional JWT support (must remain stateful)
- Reference Swagger docs included

## Testing
- Table-driven integration tests verifying complete workflows
- Stateful test cases (actions have persistent effects)

## Notes
- Can be extended with full RealWorld spec entities