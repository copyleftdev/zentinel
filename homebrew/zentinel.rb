class Zentinel < Formula
  desc "Static analysis that doesn't waste your time — 422 rules, 4 languages, 4 tiers"
  homepage "https://github.com/copyleftdev/zentinel"
  version "0.4.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/copyleftdev/zentinel/releases/download/v#{version}/zent-macos-aarch64.tar.gz"
      # sha256 "UPDATE_AFTER_RELEASE"
    else
      url "https://github.com/copyleftdev/zentinel/releases/download/v#{version}/zent-macos-x86_64.tar.gz"
      # sha256 "UPDATE_AFTER_RELEASE"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/copyleftdev/zentinel/releases/download/v#{version}/zent-linux-aarch64.tar.gz"
      # sha256 "UPDATE_AFTER_RELEASE"
    else
      url "https://github.com/copyleftdev/zentinel/releases/download/v#{version}/zent-linux-x86_64.tar.gz"
      # sha256 "UPDATE_AFTER_RELEASE"
    end
  end

  def install
    bin.install Dir["zent-*"].first => "zent"
  end

  test do
    assert_match "Usage:", shell_output("#{bin}/zent help 2>&1")
  end
end
