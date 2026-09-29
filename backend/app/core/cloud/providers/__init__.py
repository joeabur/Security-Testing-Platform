"""One module per cloud provider, each implementing the same
`(CloudTarget, credential) -> list[BucketExposure]` shape from
`app.core.cloud.contract` — see `aws.py` for the one provider this phase
ships, and `docs/roadmap.md` for why `azure`/`gcp` are deferred rather than
stubbed with a fabricated result.
"""
