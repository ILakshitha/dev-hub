---
title: Creating a Pull Request
sidebar_position: 44
tags: [best-practices, pr-creating]
---


# Best Practice: Pull Request Title & Description Templates

## Why This Matters

Consistent PR titles and descriptions make a repo easier to work with for everyone. When PRs have clear context, reviews go faster, history stays readable, and it's much easier to understand *why* a change was made when looking back later.

Some PRs have great context, others are just "fixed stuff" — the difference is almost always whether a title convention and description template are being used. Below is a recommended approach that works well for repos with multiple contributors.

---

## 1. PR Title Convention

A good PR title follows this format:

```
<type>(<scope>): <short summary>
```

**Examples:**
```
feat(auth): add OAuth2 login support
fix(api): handle null response from payment gateway
docs(readme): update installation steps
chore(deps): bump lodash to 4.17.21
```

### Recommended `type` values

| Type       | Use when...                                      |
|------------|---------------------------------------------------|
| `feat`     | Adding a new feature                               |
| `fix`      | Fixing a bug                                       |
| `docs`     | Documentation-only changes                         |
| `style`    | Formatting, whitespace, no logic change            |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf`     | Performance improvement                            |
| `test`     | Adding or updating tests                           |
| `chore`    | Tooling, dependencies, build config, etc.          |

`<scope>` is optional but encouraged — it's the module, feature, or area affected (e.g. `auth`, `api`, `ui`, `deps`).

> This convention also keeps git history readable and makes it possible to auto-generate changelogs later if needed.

---

## 2. PR Description Template

A `PULL_REQUEST_TEMPLATE.md` file placed at:

```
.github/PULL_REQUEST_TEMPLATE.md
```

will automatically load into the description box whenever someone opens a new PR on GitHub — no extra steps required from the contributor.

A solid template looks like this:

```markdown
## Description
<!-- What does this PR do? Why is it needed? -->


## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactor / chore
- [ ] CI/CD change
- [ ] Test update 
- [ ] Database update
- [ ] Other

## Changes Made
<!-- List of key changes -->
- 
- 

## How to Test
<!-- Steps to verify this works -->
1. 
2. 

## Screenshots (if applicable)

## Checklist
- [ ] Code follows the project's guidelines
- [ ] Self-reviewed my own code
- [ ] Added/updated documentation
- [ ] No new warnings or errors introduced
- [ ] All tests pass locally

## Additional Notes
<!-- Anything reviewers should know -->

```

### What each section is for

- **Description** — the "why," not just the "what." Reviewers shouldn't have to guess intent.
- **Related Issue** — links the PR to tracking. Using `Closes #123` auto-closes the issue on merge.
- **Type of Change** — quick scan for reviewers to know what kind of risk they're reviewing.
- **Changes Made** — a bullet-point summary, especially useful for large PRs.
- **How to Test** — saves reviewers time; they shouldn't have to reverse-engineer how to verify a change.
- **Checklist** — a lightweight self-review gate before requesting review.

---

## 3. How to Apply This

- Add the template file to `.github/PULL_REQUEST_TEMPLATE.md` in the repo — it'll auto-populate for every new PR.
- Follow the title convention above (`type(scope): summary`) when naming PRs.
- If a change doesn't fit neatly into one type, pick the closest one and clarify in the description.

---

## FAQ

**Q: Can checklist items be skipped?**
A: Leave them unchecked rather than deleting them — it's a visible signal to reviewers about what's still outstanding.

**Q: What if different templates are needed for bug fixes vs. features?**
A: GitHub supports multiple templates under `.github/PULL_REQUEST_TEMPLATE/`, letting contributors pick the right one when opening a PR.

---
