PYTHON ?= python

N ?= 200
MAX_MESSAGES ?= 400
MAX_TOOL_HOPS ?= 4
LOCAL_EVAL_N ?= 20
MAX_KAGGLE_STATUS_AGE_MIN ?= 30
VALIDATION_N ?= 20
VALIDATION_BUDGET_PER_MODEL ?= 3000
VALIDATION_MODELS ?= gpt_oss,gemma
VALIDATION_MAX_TOOL_HOPS ?= 8
VALIDATION_RAW_OUT ?= research/results/validation-raw.latest.jsonl
EXPERIMENT_N ?= 5
EXPERIMENT_FAMILIES ?= direct_exfil_suppress_once,direct_exfil_suppress_stop,direct_exfil_suppress_no_summary,direct_exfil_exactly_once,direct_exfil_minimal_function
EXPERIMENT_BANK ?= research/results/candidate_bank.suppress_ab.jsonl
EXPERIMENT_OUT ?= research/results/suppress-ab-local.latest.json
EXPERIMENT_GGUF_OUT ?= research/results/suppress-ab-gguf.latest.json
EXPERIMENT_GGUF_RAW_OUT ?= research/results/suppress-ab-gguf.raw.jsonl

COMPETITION ?= ai-agent-security-multi-step-tool-attacks
KERNEL_SLUG ?= canqiang/aiagsec-static-c1-n600
KAGGLE_STATUS_JSON ?= submissions/manifests/kaggle-status.latest.json

SAMPLE_BANK ?= research/results/candidate_bank.sample.jsonl
SCORED_BANK ?= research/results/candidate_bank.suppress.jsonl
VALIDATION_SUMMARY ?= research/results/validation-summary.latest.json
SUBMISSION_CSV ?= /tmp/aiagsec-submission.csv
MANIFEST_OUT ?= /tmp/aiagsec-pre-submit.json
MANIFEST_SUMMARY ?= /tmp/aiagsec-pre-submit.md

PY_FILES := $(shell find src tools research -name '*.py' -not -path '*/__pycache__/*' | sort)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make ci              SDK-free checks for GitHub Actions"
	@echo "  make check           full local gate; requires competition_files/aicomp_sdk"
	@echo "  make manifest-smoke  build throwaway pre-submit manifest under /tmp"
	@echo "  make submit-ready    strict pre-submit manifest; fails until validation evidence exists"
	@echo "  make manifest-local  refresh tracked latest manifest and summary"
	@echo "  make submission-csv  write official four-row commit-run CSV"
	@echo "  make kaggle-status   refresh Kaggle status JSON"
	@echo "  make validation-gguf run real GGUF validation and write summary"
	@echo "  make validation-kernel build self-contained Kaggle validation kernel"
	@echo "  make push-validation-kernel push validation kernel with explicit T4"
	@echo "  make experiment-suppress-ab run local suppressor A/B experiment"
	@echo "  make experiment-gguf-suppress-ab run GGUF suppressor A/B experiment"

.PHONY: compile
compile:
	$(PYTHON) -m py_compile $(PY_FILES)

.PHONY: parity
parity:
	$(PYTHON) tools/check_submission_notebook.py

.PHONY: bank-sample
bank-sample:
	$(PYTHON) research/candidate_families.py --families all --n 2 --out $(SAMPLE_BANK)

.PHONY: bank-suppress
bank-suppress:
	$(PYTHON) research/candidate_families.py --families direct_exfil_suppress_once --n 5 --out $(SCORED_BANK)

.PHONY: bank-suppress-ab
bank-suppress-ab:
	$(PYTHON) research/candidate_families.py --families $(EXPERIMENT_FAMILIES) --n $(EXPERIMENT_N) --out $(EXPERIMENT_BANK)

.PHONY: bank-lint
bank-lint: bank-sample
	$(PYTHON) tools/lint_candidate_bank.py $(SAMPLE_BANK)

.PHONY: bank-scored-lint
bank-scored-lint: bank-suppress
	$(PYTHON) tools/lint_candidate_bank.py $(SCORED_BANK) --scored --max-total-messages $(MAX_MESSAGES) --fail-on-warning

.PHONY: sweep-bank
sweep-bank:
	$(PYTHON) research/candidate_families.py --families read_post_exfil,read_post_stack --n 30 --out research/results/high_raw_sweep.jsonl
	$(PYTHON) research/candidate_families.py --families sentinel_stack,read_post_no_secret --n 12 --start 1000 --out research/results/high_raw_sweep.controls.jsonl
	cat research/results/high_raw_sweep.controls.jsonl >> research/results/high_raw_sweep.jsonl
	rm -f research/results/high_raw_sweep.controls.jsonl
	$(PYTHON) tools/lint_candidate_bank.py research/results/high_raw_sweep.jsonl

.PHONY: validation-notebook-check
validation-notebook-check:
	$(PYTHON) tools/check_validation_notebook.py notebooks/validation.ipynb

.PHONY: test
test:
	$(PYTHON) -m pytest tools/tests -q

.PHONY: ledger
ledger:
	$(PYTHON) tools/pull_submission_ledger.py --print

.PHONY: safe-submit
safe-submit:
	$(PYTHON) tools/safe_submit.py --kernel-folder $(KERNEL_FOLDER) --message "$(MESSAGE)"

.PHONY: ci
ci: compile parity validation-notebook-check bank-lint bank-scored-lint test

.PHONY: sdk-present
sdk-present:
	@test -d competition_files/aicomp_sdk || (echo "competition_files/aicomp_sdk missing; download the competition SDK before running SDK gates." >&2; exit 2)

.PHONY: audit
audit: sdk-present
	$(PYTHON) tools/audit_attack.py --n $(N)

.PHONY: bank-eval
bank-eval: sdk-present bank-suppress
	$(PYTHON) tools/eval_candidate_bank.py $(SCORED_BANK) --max-tool-hops $(MAX_TOOL_HOPS)

.PHONY: local-eval
local-eval: sdk-present
	$(PYTHON) tools/local_eval.py compliant --n $(LOCAL_EVAL_N)

.PHONY: submission-csv
submission-csv:
	$(PYTHON) tools/write_submission_csv.py --out $(SUBMISSION_CSV)

.PHONY: validation-summary
validation-summary:
	$(PYTHON) tools/validate_validation_summary.py $(VALIDATION_SUMMARY)

.PHONY: validation-gguf
validation-gguf:
	$(PYTHON) tools/run_gguf_validation.py \
		--n $(VALIDATION_N) \
		--models $(VALIDATION_MODELS) \
		--budget-per-model $(VALIDATION_BUDGET_PER_MODEL) \
		--max-tool-hops $(VALIDATION_MAX_TOOL_HOPS) \
		--out $(VALIDATION_SUMMARY) \
		--raw-out $(VALIDATION_RAW_OUT)

.PHONY: experiment-suppress-ab
experiment-suppress-ab: sdk-present
	$(PYTHON) tools/run_candidate_experiment.py \
		--families $(EXPERIMENT_FAMILIES) \
		--n $(EXPERIMENT_N) \
		--bank-out $(EXPERIMENT_BANK) \
		--out $(EXPERIMENT_OUT) \
		--fail-on-warning

.PHONY: experiment-gguf-suppress-ab
experiment-gguf-suppress-ab: sdk-present bank-suppress-ab
	$(PYTHON) tools/run_gguf_bank_experiment.py \
		--bank $(EXPERIMENT_BANK) \
		--models $(VALIDATION_MODELS) \
		--budget-per-model $(VALIDATION_BUDGET_PER_MODEL) \
		--max-tool-hops $(VALIDATION_MAX_TOOL_HOPS) \
		--out $(EXPERIMENT_GGUF_OUT) \
		--raw-out $(EXPERIMENT_GGUF_RAW_OUT)

.PHONY: validation-kernel
validation-kernel:
	$(PYTHON) tools/prepare_validation_kernel.py

.PHONY: push-validation-kernel
push-validation-kernel: validation-kernel
	$(PYTHON) tools/push_kaggle_kernel.py kaggle_push/validation

.PHONY: submit-readiness-kernel
submit-readiness-kernel:
	$(PYTHON) tools/prepare_submit_readiness_kernel.py

.PHONY: push-submit-readiness-kernel
push-submit-readiness-kernel: submit-readiness-kernel
	$(PYTHON) tools/push_kaggle_kernel.py kaggle_push/submit_readiness

.PHONY: manifest-smoke
manifest-smoke: sdk-present bank-suppress
	$(PYTHON) tools/build_submission_manifest.py \
		--n $(N) \
		--machine-shape NvidiaTeslaT4 \
		--candidate-bank $(SCORED_BANK) \
		--candidate-bank-scored \
		--eval-candidate-bank \
		--allow-missing-validation \
		--kaggle-status-json $(KAGGLE_STATUS_JSON) \
		--description "local pre-submit smoke" \
		--out $(MANIFEST_OUT) \
		--summary-md $(MANIFEST_SUMMARY)

.PHONY: check
check: ci audit bank-eval local-eval manifest-smoke

.PHONY: submit-ready
submit-ready: sdk-present bank-suppress submission-csv kaggle-status
	$(PYTHON) tools/build_submission_manifest.py \
		--n $(N) \
		--machine-shape NvidiaTeslaT4 \
		--candidate-bank $(SCORED_BANK) \
		--candidate-bank-scored \
		--eval-candidate-bank \
		--validation-summary $(VALIDATION_SUMMARY) \
		--kaggle-status-json $(KAGGLE_STATUS_JSON) \
		--max-kaggle-status-age-min $(MAX_KAGGLE_STATUS_AGE_MIN) \
		--submission-csv $(SUBMISSION_CSV) \
		--require-submission-csv \
		--description "strict suppress-once n$(N) pre-submit evidence" \
		--out $(MANIFEST_OUT) \
		--summary-md $(MANIFEST_SUMMARY)

.PHONY: manifest-local
manifest-local: sdk-present bank-suppress
	$(PYTHON) tools/build_submission_manifest.py \
		--n $(N) \
		--machine-shape NvidiaTeslaT4 \
		--candidate-bank $(SCORED_BANK) \
		--candidate-bank-scored \
		--eval-candidate-bank \
		--allow-missing-validation \
		--kaggle-status-json $(KAGGLE_STATUS_JSON) \
		--description "suppress-once n$(N) local pre-submit evidence with live Kaggle status" \
		--note "Live Kaggle status shows no pending refs when status JSON is fresh; GGUF validation summary and commit-run CSV must be attached before submit." \
		--out submissions/manifests/pre-submit-local.latest.json \
		--summary-md docs/superpowers/results/pre-submit-local.latest.md

.PHONY: kaggle-status
kaggle-status:
	$(PYTHON) tools/kaggle_status.py \
		--competition $(COMPETITION) \
		--kernel $(KERNEL_SLUG) \
		--out $(KAGGLE_STATUS_JSON)
