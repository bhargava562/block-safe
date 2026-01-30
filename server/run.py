"""
BlockSafe Server Runner
Entry point for running the API server
"""

import uvicorn


def main():
    """Run the BlockSafe API server"""
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
