# Development live Gate bind/shutdown generator output

Generated from clean Haldir commit `3a75c039c3e73b999a74741b5633ee43a0a69e97`. The offline container provisioned a disposable tmpfs fixture, and a separate container opened that fixture, opened one strict session against the pinned router, bound the real aggregate, and immediately shut it down.

The generator performed no independent verification and does not decide retention or promotion; those actions and any claim status must be established externally. The target processed zero intents and published zero commands. It does not prove authenticated control delivery, publication, credential custody, remote cleanup, production shutdown, or complete mediation. The cooperative path checks assume a trusted host; abrupt process, host, or daemon loss can require manual cleanup of campaign-named objects and the generator output root.
