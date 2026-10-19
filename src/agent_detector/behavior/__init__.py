"""Zero-cooperation network behavior observation (plan §3.1.4 / §3.3 Passive Monitor).

Watches outbound connections of local processes and records LLM API calls at
the connection level: which process, when, and which API destination. TLS
keeps call content (model names, prompts) invisible — this package records
that a call happened, never what was said. Events land in the shared
behavior_events table with source="netmon".
"""
