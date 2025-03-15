# Contributors Guide

Contributions are what make the open-source community such an amazing place to learn, inspire and create. Every contributions you make is **greatly appreciated**. Your contributions can be as simple as fixing the indentation or UI, or as complex as adding new modules and features.

## For who is this guide?

This guide is meant for users who want to contribute to the codebase of Oasis, whether that is the application code or documentation. To keep all processes streamlined and consistent, we're asking you to stick to this guide whenever contributing.

Even though the guide is made for contributors, it's also strongly recommended that the Oasis team sticks to these guidelines. After all, we're a prime example.

## What are the guidelines?

### Submitting issues

You can submit issues related to this project, but you should do it in a way that helps developers to resolve it as quickly as possible.

For that, you need to add as much valuable information as possible.

You can have this valuable information by running Oasis in debug mode:

```bash
oasis --debug -i my_project
```

**Activating debug mode will give you more information** instead of a generic error without any details.

Happy issuing ;)

### Support

We are volunteers, working hard on Oasis to add new features. Help is welcome, you can help us out by opening a PR.

* Add a GitHub Star to the project.
* Tweet about this project, or maybe blogs?

Any support is greatly appreciated! Thank you!

### First-time Open Source contributors

Please note that Oasis is beginner friendly. If you have never done open-source before, we encourage you to do so. **We will be happy and proud of your first PR ever.**

You can start by resolving any open issues.

### Branching strategy

As for our branching strategy, we're using [Release Branching](https://www.split.io/blog/the-basics-of-release-branching/).

In short, a release branch is created from the main branch when the team is ready to roll out a new version. Only necessary changes like bug fixes and final touch-ups are made. Once finalized, it merges with the main branch for deployment. Urgent fixes after the release are handled using hotfix branches, which merge back into both the release and main branches. We do not use a `develop` branch as that adds complexity.

Some examples of branches are:

* Features (`feature/*`)
* Fixes (`hotfix/*` or simply `fix/*`)
* Dependency updates (`deps/*`)
* Releases (`release/*`)

Do mind that these branch names do only not apply when there's already an issue for the pull request. In that case we use the following scheme: `[issue number][issue title]`. This can be done [automatically](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-a-branch-for-an-issue) too.

This is how it looks like and works. The difference here is that we don't have a develop branch (so the purple dots that are connected with its mainline should not be included).

<img src="https://wac-cdn.atlassian.com/dam/jcr:cc0b526e-adb7-4d45-874e-9bcea9898b4a/04%20Hotfix%20branches.svg?cdnVersion=1871" alt="drawing" width="600"/>

So in short:

1. PR with feature/fix is opened
1. PR is merged into release branch
1. When we release a new version, release branch is merged to main

### Commit messages

As for commits, we prefer using [Conventional Commit Messages](https://gist.github.com/qoomon/5dfcdf8eec66a051ecd85625518cfd13). When working in any of the branches listed above (if there's an existing issue for it), close it using a [closing keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword). For more information regarding Conventional Commit Messages, see <https://www.conventionalcommits.org/en/v1.0.0/> as well. 