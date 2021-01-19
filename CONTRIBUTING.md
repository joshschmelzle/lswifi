# Contribution Guidelines

To get the greatest chance of helpful responses, please observe the
following additional notes.

## Questions

The GitHub issue tracker is for *bug reports* and *feature requests*. Please do
not use it to ask questions about usage. These questions should
instead be directed to through other channels.

## Code

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or bug.
2. Fork the repository on GitHub to start making your changes.
3. Please write a test which shows that the bug was fixed or that the feature works as expected.
4. Check that your code follows the [Style Guide](https://github.com/joshschmelzle/lswifi/blob/main/STYLEGUIDE.md).
5. Send a pull request.

## Good Bug Reports

Please be aware of the following things when filing bug reports:

1. Avoid raising duplicate issues. *Please* use the GitHub issue search feature
   to check whether your bug report or feature request has been mentioned in
   the past. Duplicate bug reports and feature requests are a huge maintenance
   burden on the limited resources of the project. If it is clear from your
   report that you would have struggled to find the original, that's ok, but
   if searching for a selection of words in your issue title would have found
   the duplicate then the issue will likely be closed extremely abruptly.
2. When filing bug reports about exceptions or tracebacks, please include the
   *complete* traceback. Partial tracebacks, or just the exception text, are
   not helpful. Issues that do not contain complete tracebacks may be closed
   without warning.
3. Make sure you provide a suitable amount of information to work with. This
   means you should provide:

   - Guidance on **how to reproduce the issue**. Ideally, this should be a
     *small* code sample that can be run immediately by the maintainers.
     Failing that, let us know what you're doing, how often it happens, what
     environment you're using, etc. Be thorough: it prevents us needing to ask
     further questions.
   - Tell us **what you expected to happen**. When we run your example code,
     what are we expecting to happen? What does "success" look like for your
     code?
   - Tell us **what actually happens**. It's not helpful for you to say "it
     doesn't work" or "it fails". Tell us *how* it fails: do you get an
     exception? How was the actual result different from your expected result?
   - Tell us **what version you're using**, and
     **how you installed it**. Different versions behave
     differently and have different bugs.
   - Tell us **what NIC and driver** you're running this package with. Use `netsh wlan show drivers` to retrieve.
   - **Provide a packet capture** that includes a beacon from the wireless network you have issues with.

   If you do not provide all of these things, it can take us much longer to
   fix your problem. If we ask you to clarify these and you never respond, we
   will close your issue without fixing it.
