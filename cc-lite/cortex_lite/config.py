class CadmiumTheme:
    RED    = "\033[38;2;227;0;34m"
    ORANGE = "\033[38;2;237;135;45m"
    YELLOW = "\033[38;2;255;246;0m"
    GREEN  = "\033[38;2;0;107;60m"
    BLUE   = "\033[38;2;60;120;255m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    @classmethod
    def paint(cls, text, color):
        return f"{color}{text}{cls.RESET}"
