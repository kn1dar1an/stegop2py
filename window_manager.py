import curses
import curses.ascii
import queue
from threading import Thread
from time import sleep
from typing import Callable


class WindowManager(Thread):
    """Class that manages the console window; handles user input for sending messages and
    displaying incomming messages. Runs on a separate thread to not block other operations 
    / loops.
    """
    def __init__(self, message_queue: queue.Queue, input_callback: Callable):
        """Class constructor.

        Args:
            message_queue (queue.Queue): Queue containing messages yet to be displayed.
            input_callback (Callable): Callback function called when a user inputs a new
                        message to send.
        """
        super(WindowManager, self).__init__()
        self.screen: curses.window
        self.scr_x = 0
        self.scr_y = 0
        self.running = False
        # Decoded messages
        self.message_queue = message_queue
        # List for storing display messages, since queue.get() removes the item
        self.display_messages = []
        self.input_buffer = ""
        self.input_callback = input_callback

    def run(self):
        """Thread start function that contains the main loop.
        Loop checks for incomming messages, and if any keys are pressed, if it corresponds
        to a valid character it is added to a buffer, if it is the backspace key the last
        character in the buffer is removed, if enter key is pressed, the input_callback
        callback is called passing the buffer string as parameter.
        """
        self.running = True
        self.screen = curses.initscr()

        # Get screen width and height
        self.scr_y, self.scr_x = self.screen.getmaxyx()

        # Curses configuration
        curses.echo()
        curses.cbreak()
        self.screen.nodelay(True)
        self.screen.keypad(True)
        self.screen.clear()
        self.screen.addstr(self.scr_y - 1, 0, "Message: ")

        while self.running:
            if not self.message_queue.empty():
                self.display_messages.insert(0, self.message_queue.get())

            # Get message
            try:
                char = self.screen.getch()
                if char == curses.ERR:
                    pass
                elif (char == curses.KEY_BACKSPACE or char == 127 or char == '\b') and self.input_buffer != "":
                    # If key was backspace, remove last character
                    self.input_buffer = self.input_buffer[:-1]
                elif (char == curses.KEY_ENTER or char == 10) and self.input_buffer != "":
                    # if enter was pressed; Enter key = 10 in ascii
                    self.input_callback(self.input_buffer)
                    self.input_buffer = ""
                else:
                    self.input_buffer += chr(char)

                self.show_messages()

            except curses.error:
                # If no input, pass
                pass

            sleep(0.001)  # Sleep for 1 ms

    def show_messages(self):
        """Function that displays messages stored in the internal string array to the 
        screen.
        """
        for i in range(0, len(self.display_messages)):
            if i > self.scr_y:
                break
            try:
                y_coord = self.scr_y - (i + 3)  # Print starting from 3 lines from the bottom
                sender, msg = self.display_messages[i]
                # Add the message sender
                who = ""
                if sender == "host":
                    who = "Friend > "
                elif sender == "self":
                    who = "You    > "
                elif sender == "system":
                    who = "System >"
                self.screen.addstr(y_coord, 0, who + msg)
                self.screen.clrtoeol()
            except curses.error:
                pass

        self.screen.addstr(self.scr_y - 1, 0, "Message: ")
        self.screen.addstr(self.input_buffer)
        self.screen.clrtoeol()
        self.screen.refresh()

    def print(self, message: str):
        """Helper function for manually printing system messages.
        """
        dm = ('system', message)
        self.display_messages.insert(0, dm)

    def stop(self):
        """Stops loop and resets terminal to default settings.
        """
        self.running = False
        self.screen.keypad(False)
        curses.nocbreak()
        curses.echo()
        curses.endwin()
