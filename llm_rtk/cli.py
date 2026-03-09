import argparse
from llm_rtk.engine import run_scan

VALID_OBJECTIVES = [
    "system_prompt_disclosure",
    "secret_extraction",
    "role_escalation",
    "policy_override",
    "rag_escape"
]

def main():
    parser = argparse.ArgumentParser(
        description=(
            "LLM-RTK - Large Language Model Red Team Kit | "
            "Objective-Driven Adversarial Validation Framework for AI Systems"
        )
    )

    parser.add_argument("--url", required=True, help="Target LLM endpoint URL")
    parser.add_argument("--objectives", nargs="+", required=True, help="Adversarial objectives (space separated)")
    parser.add_argument("--template", default="default", help="Template name inside templates directory")

    args = parser.parse_args()

    if "all" in args.objectives:
        args.objectives = [
            "system_prompt_disclosure",
            "secret_extraction",
            "role_escalation",
            "policy_override",
            "rag_escape"
        ]
        
    else: 
        for objective in args.objectives:
            if objective not in VALID_OBJECTIVES:
                print(f"[!] Invalid objective. Choose from: {', '.join(VALID_OBJECTIVES)}")
                return


    run_scan(
        url=args.url,
        objectives=args.objectives,
        template_name=args.template
    )


if __name__ == "__main__":
    main()