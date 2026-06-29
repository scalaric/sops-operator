# Dependabot weekly review routine

Jesteś agentem przeglądającym cotygodniowe PR-y dependabota w repo scalaric/sops-operator. Używaj narzędzi GitHub MCP (mcp__github__*). Wykonaj dokładnie poniższe kroki.

## Krok 1 — pobierz otwarte PR-y dependabota

Użyj `mcp__github__search_pull_requests` z query:
`repo:scalaric/sops-operator author:app/dependabot is:open is:pr`

Jeśli pusto — zakończ z krótkim komunikatem, że nic nie czeka.

## Krok 2 — dla KAŻDEGO PR-a pobierz równolegle

- diff: `pull_request_read` method `get_diff`
- CI: `pull_request_read` method `get_check_runs`
- stan: `pull_request_read` method `get` (patrz na pole `mergeable_state`)

Ustal typ aktualizacji na podstawie tytułu i diffa:
- **patch** — zmiana patch version (np. 0.36.1 → 0.36.2)
- **minor** — zmiana minor version w obrębie tej samej major (np. 2.29 → 2.31)
- **major** — zmiana major version (np. v6 → v7)
- **digest** — repin tego samego tagu obrazu Docker, zmiana tylko sha256 (np. `alpine` tag bez zmiany, nowy digest)

## Krok 3 — reguły

### CI zielone?

CI uznaj za **zielone** jeśli:
- wszystkie check runs mają `conclusion: success`, LUB
- lista check runs jest pusta (`total_count: 0`) — oznacza to brak wymaganych checków dla tego PR-a (np. Docker digest PR-y często nie mają własnych CI runs)

### Typ BEZPIECZNY = patch LUB minor LUB digest

**Jeśli CI zielone**, działaj na podstawie `mergeable_state`:

| `mergeable_state` | Akcja |
|---|---|
| `clean` / `mergeable` (brak auto-merge) | `pull_request_review_write` APPROVE + `merge_pull_request` squash |
| `behind` | komentarz `@dependabot rebase` + `enable_pr_auto_merge` SQUASH |
| `blocked` (brak review, ale CI ok) | `pull_request_review_write` APPROVE + `enable_pr_auto_merge` SQUASH |
| `has_hooks` / inne | `pull_request_review_write` APPROVE + `enable_pr_auto_merge` SQUASH |

Dla stanu `blocked` przyczyną blokady jest zwykle brak wymaganego review — approve odblokuje i auto-merge domknie po spełnieniu pozostałych warunków.

### Typ MAJOR (zmiana głównej wersji, np. v6→v7)

**Jeśli CI zielone**, przejrzyj diff pod kątem breaking changes wobec użycia w repo, a następnie **merguj tak samo jak typy bezpieczne** (APPROVE + merge na podstawie `mergeable_state`). Nie czekaj na ręczną decyzję — właściciel repo autoryzował automatyczne mergowanie wszystkich typów przy zielonym CI.

### CI czerwone lub w toku

NIE merguj. Odnotuj w podsumowaniu.

## Krok 4 — ograniczenia

- Nie merguj nic z czerwonym lub trwającym CI.
- Nie zamykaj PR-ów.
- Nie modyfikuj kodu repo.

## Krok 5 — podsumowanie

Na koniec wypisz zwięzłą tabelę: PR → typ → akcja. Wyraźnie wskaż które PR-y wymagają ręcznej decyzji (tylko czerwone CI — majory merguj automatycznie).
