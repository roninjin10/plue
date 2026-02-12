# TUI Incomplete Features

**Priority:** Low
**Area:** tui

## Description

Several TUI features are partially implemented.

## Items

### Message Parts Rendering
`tui/widgets/chat_history.zig:98`:
```zig
.parts => "[complex content]", // TODO: handle parts
```
Messages with parts (tool calls, files, reasoning) display as `[complex content]` instead of being rendered.

### Tool Result Processing
`tui/app.zig:224`:
```zig
// Tool result - update the tool call status
_ = tr_event;
// TODO: Update tool call in conversation
```
Tool results from the agent aren't reflected in the conversation display.

### Approval Flow
`tui/app.zig:322`:
```zig
if (key.matches('y', .{})) {
    // Approve
    self.state.mode = .chat;
    // TODO: Send approval
```
Pressing 'y' to approve a tool call changes mode but doesn't actually send the approval to the server.

### Diff View
`tui/app.zig:431`:
```zig
} else if (std.mem.eql(u8, parsed.command.name, "diff")) {
    // Show diffs - TODO: implement diff view mode
    try self.state.setError("Diff view not yet implemented");
```
The `/diff` command displays an error instead of showing diffs.

## Files

- `tui/widgets/chat_history.zig`
- `tui/app.zig`
