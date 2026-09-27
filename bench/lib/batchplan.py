"""Read the recorded batch inventory without consulting today's adapter configuration."""


def parse_plan(text, harness):
    plan = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            return None
        if parts[0] == harness:
            plan.append({"variant": parts[1], "steps": " ".join(parts[2:])})
    return plan or None
