# Rule licensing

## SigmaHQ rules (`windows/`, `linux/`, `cloud/aws_*.yml`)

Rules whose first line reads `# Vendored unmodified from SigmaHQ/sigma` are copied verbatim from
<https://github.com/SigmaHQ/sigma> and remain under the **Detection Rule License (DRL) 1.1**
(<https://github.com/SigmaHQ/Detection-Rule-License>). The DRL requires that redistributed
rules keep their `author` attribution and this licence notice; both are preserved here. Each
rule's original `author`, `references` and `id` are unchanged so you can diff against upstream.

## tripline rules (`tripline_*.yml` in each plane folder)

Rules authored for this project (author `Sami Ali (tripline)`) are released under the repository
MIT licence **and** under the DRL 1.1, so they can be contributed back to SigmaHQ without
relicensing.
