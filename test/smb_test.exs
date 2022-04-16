defmodule SmbTest do
  use ExUnit.Case
  doctest Smb

  test "greets the world" do
    assert Smb.hello() == :world
  end
end
