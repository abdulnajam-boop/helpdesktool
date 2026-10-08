# Help Desk observability animations

## Source inspiration
https://github.com/yihui-dev/awesome-opus5-5-videos (MIT licensed prompt collection; prompts are inspiration, not a drop-in runtime).

## Scope
Add a read-only animated incident timeline and device/network health graph to the existing frontend. Render from sanitized API data, with reduced-motion support, tenant isolation, no secrets in client payloads, and no automatic remediation triggered by visualization. Start with mock incidents and unit tests.

## Engineering rules
- Keep the existing app operational; implement as an optional feature flag.
- Use TypeScript where the application is TypeScript; follow existing patterns otherwise.
- Respect prefers-reduced-motion, keyboard accessibility, responsive layouts, and performance budgets.
- No copyrighted media reuse without rights verification.
- Add tests and a screenshot/video preview before merge.
- Never deploy or merge without review.

## Implementation checklist
- [ ] Inspect existing UI, dependencies, routing, and test setup.
- [ ] Select animation technology appropriate to the app (SVG/CSS/Canvas/GSAP/Three.js).
- [ ] Implement the smallest demonstrable component with mock data.
- [ ] Add feature flag, fallback, accessibility, and tests.
- [ ] Run lint/build/tests and document demo instructions.
- [ ] Open PR for review.
