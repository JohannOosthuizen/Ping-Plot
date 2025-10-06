# Ping-Plot

A multi-target ping monitoring tool with a dark-themed GUI for real-time network latency visualization.

![Ping-Plot Screenshot](https://github.com/JohannOosthuizen/Ping-Plot/blob/master/images/full-screen-single-ping.jpg)  

![Ping-Plot Screenshot](https://github.com/JohannOosthuizen/Ping-Plot/blob/master/images/full-screen-double-ping.jpg)


## Features

*   **Multi-Target Pinging:** Monitor multiple IP addresses or hosts simultaneously.
*   **Real-Time Graphing:** Live plots of Round-Trip Time (RTT) for each target using Matplotlib.
*   **Statistical Analysis:** View minimum, maximum, and average RTT for each target over a configurable time window.
*   **Configurable Thresholds:** Set custom warning and error RTT thresholds, which are visualized on the graphs.
*   **Data Logging:** All ping data is logged to `ping_history.csv` for later analysis.
*   **Hop Discovery:** Automatically discover and add intermediate network hops (routers) as targets using `tracert`/`traceroute`.
*   **Customizable UI:**
    *   Switch between Dark and Light themes.
    *   Toggle fullscreen mode for the application and individual plots.
    *   Adjust the time window for the displayed data (from 10 seconds to 24 hours).
*   **Audio Alerts:** Optional sound alerts for when a target's status changes from down to up, or up to down.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/JohannOosthuizen/Ping-Plot.git
    cd Ping-Plot
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    *   **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the application, simply execute the `app.py` script:

```bash
python app.py
```

The application will start with two default targets: `8.8.8.8` (Google's DNS) and your local default gateway. You can add or remove targets using the UI.

## Binaries

Pre-compiled binaries for Windows, macOS, and Linux are automatically built for each push to the `main` branch. You can download them from the "Actions" tab in the GitHub repository. Look for the latest workflow run and download the artifacts.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


## Developed by

Johann Oosthuizen
