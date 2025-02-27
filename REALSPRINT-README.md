# Update to the latest version of Nomad

- Create a new branch for the release (e.g. `release/1.3.1-rs`) from the latest RealSprint `release/*.*.*-rs` branch.
- Merge the changes from latest upstream release tag (e.g. `v1.3.1`) into the new branch.
- Make sure patches in rs-nomad-patch.patch are still applied.
- Push the new branch to the origin repository (realsprint/nomad).
- Make sure all builds pass
- If all builds pass, create a release on github.
  - Trigger the release-workflow appropriate release branch (`release/1.3.1-rs-1` for example)
  - Download the zipped amd64 binary from the build workflow
  - Unzip it (it's double zipped for some reason)
  - Generate a checksum file (release the release name with the name of your release) `sha256sum nomad_1.3.1-rs-1_linux_amd64.zip > nomad_1.3.1-rs-1_SHA256SUMS`
  - Create a new github-release and upload both the zip and the checksum file
