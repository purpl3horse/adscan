"""Confirm/prompt/questionary input helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from rich.console import Group
from rich.table import Table
from rich.text import Text

import adscan_core.output._state as _state
from adscan_core.output._log import (
    BRAND_COLORS,
    print_info,
    print_info_debug,
    print_telemetry_only,
    print_warning,
)
from adscan_core.output._panels import print_panel

__all__ = [
    "confirm_ask",
    "prompt_ask",
    "confirm_operation",
    "questionary_select_value",
    "questionary_checkbox_values",
    "questionary_checkbox_values_raw",
    "questionary_select_index",
    "install_prompt_logging_wrappers",
]

# Prompt wrapper state
_ORIGINAL_PROMPT_ASK: Optional[Callable[..., Any]] = None
_ORIGINAL_CONFIRM_ASK: Optional[Callable[..., Any]] = None
_PROMPT_LOGGING_WRAPPERS_INSTALLED = False


def _classify_prompt_answer(
    answer_text: str,
    *,
    password_mode: bool,
    prompt_message: str = "",
) -> str:
    """Best-effort classification for prompt answer sanitization."""
    from adscan_core import prompting

    return prompting.classify_prompt_answer(
        answer_text,
        password_mode=password_mode,
        prompt_message=prompt_message,
    )


def _logged_prompt_ask(*prompt_args: Any, **kwargs: Any) -> str:
    """Prompt.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_prompt_ask(
        *prompt_args,
        original_prompt_ask=_ORIGINAL_PROMPT_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def _logged_confirm_ask(*confirm_args: Any, **kwargs: Any) -> bool:
    """Confirm.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_confirm_ask(
        *confirm_args,
        original_confirm_ask=_ORIGINAL_CONFIRM_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def install_prompt_logging_wrappers() -> None:
    """Install Prompt/Confirm wrappers to centrally log questions and answers."""
    global _ORIGINAL_PROMPT_ASK, _ORIGINAL_CONFIRM_ASK
    global _PROMPT_LOGGING_WRAPPERS_INSTALLED

    if _PROMPT_LOGGING_WRAPPERS_INSTALLED:
        return

    from rich.prompt import Confirm, Prompt

    _ORIGINAL_PROMPT_ASK = Prompt.ask
    _ORIGINAL_CONFIRM_ASK = Confirm.ask
    Prompt.ask = _logged_prompt_ask  # type: ignore[assignment]
    Confirm.ask = _logged_confirm_ask  # type: ignore[assignment]
    _PROMPT_LOGGING_WRAPPERS_INSTALLED = True


def confirm_ask(prompt: str, default: bool) -> bool:
    """Ask a yes/no confirmation prompt with centralized prompt logging."""
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Confirm

        return bool(Confirm.ask(prompt, default=default))
    except Exception as exc:
        print_info_debug(
            f"[confirm] Fallback to default for '{prompt}': {default} ({type(exc).__name__})"
        )
        answer_text = "Yes" if bool(default) else "No"
        print_telemetry_only(f"[confirm][answer] {prompt}: {answer_text}")
        return default


def prompt_ask(
    prompt: str,
    default: str | None = None,
    *,
    password: bool = False,
    **kwargs: Any,
) -> str:
    """Ask a text prompt with centralized prompt logging and safe fallback."""
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Prompt

        answer = Prompt.ask(prompt, default=default, password=password, **kwargs)
        return "" if answer is None else str(answer)
    except Exception as exc:
        fallback = "" if default is None else str(default)
        print_info_debug(
            f"[prompt] Fallback to default for '{prompt}': "
            f"{_state.mark_sensitive(fallback, _classify_prompt_answer(fallback, password_mode=password, prompt_message=prompt))} "
            f"({type(exc).__name__})"
        )
        answer_tag = "[prompt][password][answer]" if password else "[prompt][answer]"
        data_type = _classify_prompt_answer(
            fallback,
            password_mode=password,
            prompt_message=prompt,
        )
        print_telemetry_only(
            f"{answer_tag} {prompt}: {_state.mark_sensitive(fallback, data_type)}"
        )
        return fallback


def questionary_select_value(
    *,
    title: str,
    options: list[str],
) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    from adscan_core import prompting

    return prompting.questionary_select_value(title=title, options=options)


def questionary_checkbox_values(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
    shell: object | None = None,
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    if not options:
        return None
    resolved_defaults = (
        [str(value) for value in default_values if str(value).strip()]
        if default_values is not None
        else [str(option) for option in options if str(option).strip()]
    )
    if _state._should_disable_prompt_interaction(shell):
        print_info_debug(
            "[questionary] Non-interactive; selecting default checkbox values "
            f"for '{title}': {resolved_defaults}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{_state.mark_sensitive(str(resolved_defaults), 'text')}"
        )
        return resolved_defaults

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_values = questionary_checkbox_values_raw(
            title=title,
            options=options,
            default_values=resolved_defaults,
        )
    except KeyboardInterrupt:
        _state._emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.checkbox"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.checkbox failed: {type(exc).__name__}: {exc}"
        )
        return None
    if selected_values is None:
        return None
    print_info_debug(f"[questionary] Selected: {selected_values}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {_state.mark_sensitive(str(selected_values), 'text')}"
    )
    return selected_values


def questionary_checkbox_values_raw(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
) -> list[str] | None:
    """Render Questionary checkbox without extra logging logic."""
    from adscan_core import prompting

    return prompting.questionary_checkbox_values_raw(
        title=title,
        options=options,
        default_values=default_values,
    )


def _questionary_style(questionary_module: Any) -> Any:
    """Return shared Questionary style used across prompts."""
    from adscan_core import prompting

    return prompting.questionary_style(questionary_module)


def questionary_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int = 0,
    shell: object | None = None,
) -> int | None:
    """Select option index via Questionary with centralized fallback/logging."""
    if not options:
        return None

    resolved_default_idx = default_idx
    if resolved_default_idx < 0 or resolved_default_idx >= len(options):
        resolved_default_idx = 0

    if _state._should_disable_prompt_interaction(shell):
        print_info_debug(
            "[questionary] Non-interactive; selecting default "
            f"idx={resolved_default_idx}: {options[resolved_default_idx]}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{_state.mark_sensitive(str(options[resolved_default_idx]), 'text')}"
        )
        return resolved_default_idx

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_value = questionary_select_value(title=title, options=options)
    except KeyboardInterrupt:
        _state._emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.select"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.select failed: {type(exc).__name__}: {exc}, "
            "falling back to numeric selection."
        )
        return _fallback_numeric_select_index(
            title=title, options=options, default_idx=resolved_default_idx
        )
    if selected_value is None:
        print_info_debug(f"[questionary] Cancelled: {title}")
        print_telemetry_only(f"[questionary][answer] {title}: [cancelled]")
        return None

    print_info_debug(f"[questionary] Selected: {selected_value}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {_state.mark_sensitive(str(selected_value), 'text')}"
    )
    try:
        return options.index(selected_value)
    except ValueError:
        return None


def _fallback_numeric_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int,
) -> int | None:
    """Fallback select menu using Rich numbered prompt."""
    if not options:
        return None

    print_info(f"[bold]{title}[/bold]")
    for idx, option in enumerate(options, start=1):
        print_info(f"  {idx}. {option}")

    default_number = (default_idx + 1) if 0 <= default_idx < len(options) else 1
    try:
        from rich.prompt import IntPrompt

        choice_num = IntPrompt.ask(
            "Enter a number (0 to cancel)",
            default=default_number,
        )
    except Exception:
        return None

    if choice_num == 0:
        return None
    if 1 <= choice_num <= len(options):
        return choice_num - 1
    return None


def confirm_operation(
    operation_name: str,
    description: str,
    context: Optional[Dict[str, str]] = None,
    default: bool = True,
    icon: str = "🔍",
    show_panel: bool = True,
) -> bool:
    """Display a professional confirmation prompt for an operation.

    This function provides a rich, informative prompt that helps users understand
    what an operation will do before confirming it. It can display context information
    in a structured format and uses ADscan brand styling.

    Args:
        operation_name: Name of the operation (e.g., "SMB Service Scan")
        description: Brief description of what the operation does
        context: Optional dict of contextual information to display (e.g., {"Domain": "example.local"})
        default: Default answer (True = yes, False = no)
        icon: Emoji icon to display with the operation name
        show_panel: Whether to show a panel with context info (if False, shows compact format)

    Returns:
        bool: True if user confirmed, False otherwise

    Example:
        >>> confirmed = confirm_operation(
        ...     "ADCS Detection",
        ...     "Searches for Active Directory Certificate Services in the domain",
        ...     context={"Domain": "example.local", "PDC": "dc.example.local"},
        ...     icon="🔐"
        ... )
    """
    # Build the prompt message
    if show_panel and context:
        # Create a context table
        context_table = Table.grid(padding=(0, 2))
        context_table.add_column(style="bold cyan", justify="right")
        context_table.add_column(style="white")

        for key, value in context.items():
            context_table.add_row(f"{key}:", value)

        # Create a panel with operation info
        panel_content = Group(
            Text(description, style="white"),
            Text(""),  # Empty line
            context_table,
        )

        print_panel(
            panel_content,
            title=f"{icon} {operation_name}",
            title_align="left",
            border_style=BRAND_COLORS["info"],
            padding=(1, 2),
            spacing="none",
        )
        prompt_text = "Proceed with this operation?"
    else:
        # Compact format without panel
        if context:
            context_str = " ".join([f"{k}: {v}" for k, v in context.items()])
            prompt_text = f"{icon} {operation_name} - {description} ({context_str})"
        else:
            prompt_text = f"{icon} {operation_name} - {description}"

    # Show confirmation prompt
    try:
        return confirm_ask(prompt_text, default=default)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print_warning("Operation cancelled")
        return False
