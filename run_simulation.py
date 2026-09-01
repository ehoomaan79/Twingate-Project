from zero_trust_core.simulator import run_local_demo


if __name__ == "__main__":
    result = run_local_demo()
    print("Demo result:")
    print(result["message"])
