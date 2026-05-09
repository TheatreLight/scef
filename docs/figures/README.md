# Mermaid figures exported from scef/docs

Generated from Mermaid code blocks in the Markdown documentation.

## Re-export

```powershell
powershell -ExecutionPolicy Bypass -File scef/docs/figures/export_png.ps1
```

The script exports all `src/*.mmd` files to `png/*.png` with white background and scale 3 by default.

| # | Markdown file | Heading | Source | PNG |
|---:|---|---|---|---|
| 1 | `architecture.md` | Module Map | `src/architecture_01_module-map.mmd` | `png/architecture_01_module-map.png` |
| 2 | `architecture.md` | Component Responsibilities | `src/architecture_02_component-responsibilities.mmd` | `png/architecture_02_component-responsibilities.png` |
| 3 | `browser-viewer.md` | Module Architecture | `src/browser-viewer_01_module-architecture.mmd` | `png/browser-viewer_01_module-architecture.png` |
| 4 | `browser-viewer.md` | Unlock Flow | `src/browser-viewer_02_unlock-flow.mmd` | `png/browser-viewer_02_unlock-flow.png` |
| 5 | `container-format.md` | Overview (top row) | `src/container-format_01a_overview-top.mmd` | `png/container-format_01a_overview-top.png` |
| 5a | `container-format.md` | Overview (bottom row) | `src/container-format_01b_overview-bottom.mmd` | `png/container-format_01b_overview-bottom.png` |
| 5b | composed | Overview (combined) | `compose_two_row_flow.py` | `png/container-format_01_overview.png` |
| 6 | `data-flows.md` | Key Derivation Flow | `src/data-flows_01_key-derivation-flow.mmd` | `png/data-flows_01_key-derivation-flow.png` |
| 7 | `data-flows.md` | Container Creation Flow (init row) | `src/data-flows_02a_container-creation-init.mmd` | `png/data-flows_02a_container-creation-init.png` |
| 7a | `data-flows.md` | Container Creation Flow (data row) | `src/data-flows_02b_container-creation-data.mmd` | `png/data-flows_02b_container-creation-data.png` |
| 7b | composed | Container Creation Flow (combined) | `compose_two_row_flow.py` | `png/data-flows_02_container-creation-flow.png` |
| 8 | `data-flows.md` | Add File Flow (prepare row) | `src/data-flows_03a_add-file-prepare.mmd` | `png/data-flows_03a_add-file-prepare.png` |
| 8a | `data-flows.md` | Add File Flow (write row) | `src/data-flows_03b_add-file-write.mmd` | `png/data-flows_03b_add-file-write.png` |
| 8b | composed | Add File Flow (combined) | `compose_two_row_flow.py` | `png/data-flows_03_add-file-flow.png` |
| 9 | `data-flows.md` | Open Container Flow (init + magic check) | `src/data-flows_04a_open-container-init.mmd` | `png/data-flows_04a_open-container-init.png` |
| 9a | `data-flows.md` | Open Container Flow (KEK + HMAC + unwrap) | `src/data-flows_04b_open-container-loop.mmd` | `png/data-flows_04b_open-container-loop.png` |
| 9b | `data-flows.md` | Open Container Flow (outcome) | `src/data-flows_04c_open-container-outcome.mmd` | `png/data-flows_04c_open-container-outcome.png` |
| 9c | composed | Open Container Flow (combined, 3 rows) | `compose_two_row_flow.py` | `png/data-flows_04_open-container-readmeta-flow.png` |
| 10 | `data-flows.md` | Extract Flow (select row) | `src/data-flows_05a_extract-select.mmd` | `png/data-flows_05a_extract-select.png` |
| 10a | `data-flows.md` | Extract Flow (verify row) | `src/data-flows_05b_extract-verify.mmd` | `png/data-flows_05b_extract-verify.png` |
| 10b | composed | Extract Flow (combined) | `compose_two_row_flow.py` | `png/data-flows_05_extract-flow.png` |
| 11 | `data-flows.md` | Header Sync Flow (prepare row) | `src/data-flows_06a_header-sync-prepare.mmd` | `png/data-flows_06a_header-sync-prepare.png` |
| 11a | `data-flows.md` | Header Sync Flow (write row) | `src/data-flows_06b_header-sync-write.mmd` | `png/data-flows_06b_header-sync-write.png` |
| 11b | composed | Header Sync Flow (combined) | `compose_two_row_flow.py` | `png/data-flows_06_header-sync-flow-after-every-write.png` |
| 12 | `data-flows.md` | Wrap (on create) | `src/data-flows_07_wrap-on-create.mmd` | `png/data-flows_07_wrap-on-create.png` |
| 13 | `data-flows.md` | Unwrap (on open) | `src/data-flows_08_unwrap-on-open.mmd` | `png/data-flows_08_unwrap-on-open.png` |
| 14 | `gui.md` | Architecture | `src/gui_01_architecture.mmd` | `png/gui_01_architecture.png` |
| 15 | `gui.md` | Main.qml | `src/gui_02_main-qml.mmd` | `png/gui_02_main-qml.png` |
