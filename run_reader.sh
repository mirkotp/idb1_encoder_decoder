#!/bin/bash
source .venv/bin/activate
PYTHONPATH=src streamlit run src/idb1/reader_gui.py
